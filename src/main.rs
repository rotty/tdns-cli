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
use tokio_tcp::TcpStream;
use tokio_udp::UdpSocket;
use trust_dns::{
    client::{BasicClientHandle, ClientFuture, ClientHandle},
    proto::{udp::UdpResponse, xfer::dns_multiplexer::DnsMultiplexerSerialResponse},
    rr,
    tcp::TcpClientStream,
    udp::UdpClientStream,
};

use tdns_update::{
    record::{RecordSet, RsData},
    update::{poll_server, Settings},
    util,
};

type RuntimeHandle = tokio::runtime::current_thread::Handle;

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

trait DnsOpen {
    type Client: ClientHandle;
    fn open(runtime: RuntimeHandle, addr: SocketAddr) -> Self::Client;
}

struct TcpOpen;

impl DnsOpen for TcpOpen {
    type Client = BasicClientHandle<DnsMultiplexerSerialResponse>;
    fn open(runtime: RuntimeHandle, addr: SocketAddr) -> Self::Client {
        let (connect, handle) = TcpClientStream::<TcpStream>::new(addr);
        let (bg, client) = ClientFuture::new(connect, handle, None);
        runtime.spawn(bg).unwrap();
        client
    }
}

struct UdpOpen;

impl DnsOpen for UdpOpen {
    type Client = BasicClientHandle<UdpResponse<tokio_udp::UdpSocket>>;
    fn open(runtime: RuntimeHandle, addr: SocketAddr) -> Self::Client {
        let stream = UdpClientStream::<UdpSocket>::new(addr);
        let (bg, client) = ClientFuture::connect(stream);
        runtime.spawn(bg).unwrap();
        client
    }
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
        })
    }
}

impl<O> App<O>
where
    O: DnsOpen,
{
    fn new(runtime: RuntimeHandle, settings: Settings) -> Result<Self, failure::Error> {
        let resolver = settings.resolver;
        Ok(App {
            settings: Rc::new(settings),
            runtime: runtime.clone(),
            recursor: O::open(runtime, resolver),
        })
    }
    fn run(&mut self) -> impl Future<Item = (), Error = failure::Error> {
        let handle = self.runtime.clone();
        let settings = Rc::clone(&self.settings);
        let get_authorative = util::get_ns_records(self.recursor.clone(), settings.domain.clone())
            .map_err(failure::Error::from);
        let recursor = self.recursor.clone();
        let poll_servers = {
            let settings = Rc::clone(&self.settings);
            get_authorative.and_then(move |authorative| {
                let names = authorative
                    .into_iter()
                    .filter_map(|r| r.rdata().as_ns().cloned());
                Self::poll_for_update(
                    handle.clone(),
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
            let resolve =
                util::resolve_authorative(recursor.clone(), server_name.clone()).map(move |ip| {
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
        Box::new(App::<TcpOpen>::new(runtime.handle(), settings)?.run()) as AppFuture
    } else {
        Box::new(App::<UdpOpen>::new(runtime.handle(), settings)?.run())
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
