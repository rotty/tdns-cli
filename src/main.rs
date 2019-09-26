use std::{
    convert::TryFrom,
    net::{IpAddr, SocketAddr},
    rc::Rc,
    time::Duration,
};

use failure::format_err;
use futures::{
    future::{self, Either},
    Future,
};
use structopt::StructOpt;
use tokio::{prelude::*, runtime::current_thread::Runtime};
use trust_dns::{
    client::ClientHandle,
    rr,
};

use tdns_update::{
    record::{RecordSet, RsData},
    update::{poll_server, Mode, Settings},
    util, DnsOpen, RuntimeHandle, TcpOpen, UdpOpen,
};

/// Wait for a DNS entry to obtain a specified state.
#[derive(StructOpt)]
struct Opt {
    /// Specify the recusor to use, including the port number.
    ///
    /// If not specified, the first nameserver specified in `/etc/resolv.conf`
    /// is used.
    #[structopt(long)]
    resolver: Option<SocketAddr>,
    /// Timeout in seconds for how long to wait in total for a successful
    /// update.
    #[structopt(long)]
    timeout: Option<u64>,
    /// Domain to monitor.
    domain: rr::Name,
    /// Entry to monitor.
    entry: rr::Name,
    /// Expected query response.
    expected: RsData,
    /// Excluded IP address.
    #[structopt(long)]
    exclude: Option<IpAddr>,
    /// Do not perform the update.
    #[structopt(long)]
    no_op: bool,
    /// Do not monitor nameservers for the update.
    #[structopt(long)]
    no_wait: bool,
    /// Show informational messages during execution.
    #[structopt(long, short)]
    verbose: bool,
    /// The number of seconds to wait between checking.
    #[structopt(long)]
    interval: Option<u64>,
    /// Use TCP for all DNS requests.
    #[structopt(long)]
    tcp: bool,
}

struct App<O: DnsOpen> {
    runtime: RuntimeHandle,
    recursor: O::Client,
    settings: Rc<Settings>,
}

impl TryFrom<Opt> for Settings {
    type Error = failure::Error;

    fn try_from(opt: Opt) -> Result<Self, Self::Error> {
        let resolver = opt
            .resolver
            .or_else(util::get_system_resolver)
            .ok_or_else(|| {
                format_err!("could not obtain resolver address from operating system")
            })?;
        let entry = opt.entry.append_name(&opt.domain);
        Ok(Settings {
            resolver,
            expected: RecordSet::new(entry.clone(), opt.expected),
            domain: opt.domain,
            entry,
            exclude: opt.exclude.into_iter().collect(),
            interval: Duration::from_secs(opt.interval.unwrap_or(1)),
            timeout: Duration::from_secs(opt.timeout.unwrap_or(60)),
            verbose: opt.verbose,
            mode: match (!opt.no_op, !opt.no_wait) {
                (true, true) => Mode::UpdateAndMonitor,
                (true, false) => Mode::Update,
                (false, true) => Mode::Monitor,
                (false, false) => {
                    return Err(format_err!(concat!(
                        "Both --no-op and --no-wait specified.\n",
                        "If you really wanted that, why not just use the POSIX `true` utility?"
                    )))
                }
            },
        })
    }
}

impl<O> App<O>
where
    O: DnsOpen + 'static,
{
    fn new(runtime: RuntimeHandle, settings: Settings) -> Result<Self, failure::Error> {
        let resolver = settings.resolver;
        Ok(App {
            settings: Rc::new(settings),
            runtime: runtime.clone(),
            recursor: O::open(runtime, resolver),
        })
    }

    fn run(&self) -> AppFuture {
        let runtime = self.runtime.clone();
        let recursor = self.recursor.clone();
        let settings = self.settings.clone();
        match settings.mode {
            Mode::UpdateAndMonitor => Box::new(
                Self::perform_update(runtime.clone(), recursor.clone(), settings.clone())
                    .and_then(|_| Self::wait_for_update(runtime, recursor, settings)),
            ),

            Mode::Update => Box::new(Self::perform_update(
                runtime.clone(),
                recursor.clone(),
                settings.clone(),
            )),
            Mode::Monitor => Box::new(Self::wait_for_update(runtime, recursor, settings)),
        }
    }

    fn perform_update(
        runtime: RuntimeHandle,
        mut recursor: impl ClientHandle,
        settings: Rc<Settings>,
    ) -> impl Future<Item = (), Error = failure::Error> {
        let get_soa = recursor
            .query(
                settings.domain.clone(),
                rr::DNSClass::IN,
                rr::RecordType::SOA,
            )
            .map_err(failure::Error::from);
        let get_master = {
            let settings = settings.clone();
            get_soa.and_then(move |response| {
                if let Some(soa) = response
                    .answers()
                    .first()
                    .and_then(|rr| rr.rdata().as_soa())
                {
                    Either::A(util::resolve_ip(recursor, soa.mname().clone()))
                } else {
                    Either::B(future::err(format_err!(
                        "SOA record for {} not found",
                        settings.domain
                    )))
                }
            })
        };
        get_master
            .and_then(move |master| {
                println!("master: {}", master);
                let mut server = O::open(runtime.clone(), SocketAddr::new(master, 53));
                server
                    .create(settings.get_rrset(), settings.domain.clone())
                    .map_err(failure::Error::from)
            })
            .map(|response| {
                println!("REPSONSE: {:?}", response);
            })
    }

    fn wait_for_update(
        runtime: RuntimeHandle,
        recursor: impl ClientHandle,
        settings: Rc<Settings>,
    ) -> impl Future<Item = (), Error = failure::Error> {
        let get_authorative = util::get_ns_records(recursor.clone(), settings.domain.clone())
            .map_err(failure::Error::from);
        let poll_servers = {
            let settings = Rc::clone(&settings);
            get_authorative.and_then(move |authorative| {
                let names = authorative
                    .into_iter()
                    .filter_map(|r| r.rdata().as_ns().cloned());
                Self::poll_for_update(
                    runtime.clone(),
                    recursor.clone(),
                    names,
                    Rc::clone(&settings),
                )
            })
        };
        poll_servers
            .timeout(settings.timeout)
            .map_err(|e| {
                e.into_inner().unwrap_or_else(move || {
                    format_err!(
                        "timeout; update not complete within {}ms",
                        settings.timeout.as_millis()
                    )
                })
            })
            .map(|_| ())
    }

    fn poll_for_update<I>(
        runtime: RuntimeHandle,
        recursor: impl ClientHandle,
        authorative: I,
        settings: Rc<Settings>,
    ) -> impl Future<Item = (), Error = failure::Error>
    where
        I: IntoIterator<Item = rr::Name>,
    {
        future::join_all(authorative.into_iter().map(move |server_name| {
            let handle = runtime.clone();
            let server_name = server_name.clone();
            let inner_settings = Rc::clone(&settings);
            let resolve = util::resolve_ip(recursor.clone(), server_name.clone()).map(move |ip| {
                if inner_settings.exclude.contains(&ip) {
                    None
                } else {
                    Some(O::open(handle.clone(), SocketAddr::new(ip, 53)))
                }
            });
            let server_name = server_name.clone();
            let settings = Rc::clone(&settings);
            resolve.and_then(move |maybe_server| match maybe_server {
                None => Either::A(future::ok(())),
                Some(server) => Either::B(poll_server(server.clone(), server_name, settings)),
            })
        }))
        .map(|_| ())
    }
}

type AppFuture = Box<dyn Future<Item = (), Error = failure::Error>>;

fn run(opt: Opt) -> Result<(), failure::Error> {
    let mut runtime = Runtime::new().unwrap();
    let tcp = opt.tcp;
    let settings = Settings::try_from(opt)?;
    let app = if tcp {
        App::<TcpOpen>::new(runtime.handle(), settings)?.run()
    } else {
        App::<UdpOpen>::new(runtime.handle(), settings)?.run()
    };
    runtime.block_on(app).map(|_| ())
}

fn main() {
    let opt = Opt::from_args();
    let rc = match run(opt) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("error: {}", e);
            1
        }
    };
    std::process::exit(rc);
}
