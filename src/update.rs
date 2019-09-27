use std::{
    convert::TryFrom,
    net::{IpAddr, SocketAddr},
    rc::Rc,
    time::{Duration, Instant},
};

use failure::format_err;
use futures::{
    future::{self, Either},
    Future,
};
use tokio::{prelude::*, timer::Delay};
use trust_dns::{
    client::ClientHandle,
    op::DnsResponse,
    rr::{self, Record},
};

use crate::{record::{RecordSet, RsData}, util, DnsOpen, RuntimeHandle};

#[derive(Debug, Clone)]
pub struct Settings {
    pub resolver: SocketAddr,
    pub expected: RecordSet,
    pub zone: rr::Name,
    pub entry: rr::Name,
    pub interval: Duration,
    pub timeout: Duration,
    pub verbose: bool,
    pub exclude: Vec<IpAddr>,
    pub mode: Mode,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            resolver: "127.0.0.1:53".parse().unwrap(),
            expected: RecordSet::new(Default::default(), RsData::A(Default::default())),
            zone: Default::default(),
            entry: Default::default(),
            interval: Default::default(),
            timeout: Default::default(),
            verbose: Default::default(),
            exclude: Default::default(),
            mode: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum Mode {
    UpdateAndMonitor,
    Update,
    Monitor,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::UpdateAndMonitor
    }
}

impl Settings {
    pub fn get_rrset(&self) -> rr::RecordSet {
        let mut rrset = rr::RecordSet::new(&self.entry, self.expected.record_type(), 0);
        for data in self.expected.iter_data() {
            rrset.add_rdata(data);
        }
        rrset
    }
}

#[derive(Debug, Clone)]
pub struct Update<D: DnsOpen> {
    dns: D,
    runtime: RuntimeHandle,
    recursor: D::Client,
    settings: Rc<Settings>,
}

impl<D> Update<D>
where
    D: DnsOpen + 'static,
{
    pub fn new(
        runtime: RuntimeHandle,
        mut dns: D,
        settings: Settings,
    ) -> Result<Self, failure::Error> {
        let recursor = dns.open(runtime.clone(), settings.resolver);
        Ok(Update {
            dns,
            settings: Rc::new(settings),
            runtime: runtime.clone(),
            recursor,
        })
    }

    pub fn run(&self) -> AppFuture {
        match self.settings.mode {
            Mode::UpdateAndMonitor => {
                let this = self.clone();
                Box::new(
                    self.clone()
                        .perform_update()
                        .and_then(|_| this.wait_for_update()),
                )
            }
            Mode::Update => Box::new(self.clone().perform_update()),
            Mode::Monitor => Box::new(self.clone().wait_for_update()),
        }
    }

    fn perform_update(mut self: Self) -> impl Future<Item = (), Error = failure::Error> {
        let get_soa = self
            .recursor
            .query(
                self.settings.zone.clone(),
                rr::DNSClass::IN,
                rr::RecordType::SOA,
            )
            .map_err(failure::Error::from);
        let get_master = {
            let settings = self.settings.clone();
            let recursor = self.recursor.clone();
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
                        settings.zone
                    )))
                }
            })
        };
        let mut this = self.clone();
        get_master
            .and_then(move |master| {
                println!("master: {}", master);
                let mut server = this
                    .dns
                    .open(this.runtime.clone(), SocketAddr::new(master, 53));
                server
                    .create(this.settings.get_rrset(), this.settings.zone.clone())
                    .map_err(failure::Error::from)
            })
            .map(|response| {
                println!("REPSONSE: {:?}", response);
            })
    }

    fn wait_for_update(self: Self) -> impl Future<Item = (), Error = failure::Error> {
        let get_authorative =
            util::get_ns_records(self.recursor.clone(), self.settings.zone.clone())
                .map_err(failure::Error::from);
        let poll_servers = {
            let this = self.clone();
            get_authorative.and_then(move |authorative| {
                let names = authorative
                    .into_iter()
                    .filter_map(|r| r.rdata().as_ns().cloned());
                this.poll_for_update(names)
            })
        };
        poll_servers
            .timeout(self.settings.timeout)
            .map_err(|e| {
                e.into_inner().unwrap_or_else(move || {
                    format_err!(
                        "timeout; update not complete within {}ms",
                        self.settings.timeout.as_millis()
                    )
                })
            })
            .map(|_| ())
    }

    fn poll_for_update<I>(
        self: Self,
        authorative: I,
    ) -> impl Future<Item = (), Error = failure::Error>
    where
        I: IntoIterator<Item = rr::Name>,
    {
        let runtime = self.runtime;
        let dns = self.dns;
        let recursor = self.recursor;
        let settings = self.settings;
        future::join_all(authorative.into_iter().map(move |server_name| {
            let handle = runtime.clone();
            let server_name = server_name.clone();
            let inner_settings = Rc::clone(&settings);
            let mut dns = dns.clone();
            let resolve = util::resolve_ip(recursor.clone(), server_name.clone()).map(move |ip| {
                if inner_settings.exclude.contains(&ip) {
                    None
                } else {
                    Some(dns.open(handle.clone(), SocketAddr::new(ip, 53)))
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

fn poll_entries<F>(
    mut server: impl ClientHandle,
    server_name: rr::Name,
    settings: Rc<Settings>,
    report: F,
) -> impl Future<Item = (), Error = failure::Error>
where
    F: Fn(&rr::Name, &[Record], bool) + 'static,
{
    use future::Loop;
    future::loop_fn(report, move |report| {
        let server_name = server_name.clone();
        let settings = Rc::clone(&settings);
        server
            .query(
                settings.entry.clone(),
                settings.expected.dns_class(),
                settings.expected.record_type(),
            )
            .map_err(failure::Error::from)
            .and_then(move |response: DnsResponse| {
                let answers = response.answers();
                let hit = settings.expected.satisfied_by(answers);
                report(&server_name, answers, hit);
                if hit {
                    Either::A(future::ok(Loop::Break(())))
                } else {
                    let when = Instant::now() + settings.interval;
                    Either::B(
                        Delay::new(when)
                            .map_err(failure::Error::from)
                            .map(|_| Loop::Continue(report)),
                    )
                }
            })
    })
}

fn poll_server(
    server: impl ClientHandle,
    server_name: rr::Name,
    settings: Rc<Settings>,
) -> impl Future<Item = (), Error = failure::Error> {
    poll_entries(
        server,
        server_name,
        Rc::clone(&settings),
        move |server, records, hit| {
            if settings.verbose {
                if hit {
                    println!("{}: match found", server);
                } else {
                    let rset = match RecordSet::try_from(records) {
                        Ok(rs) => format!("{}", rs.data()),
                        Err(e) => format!("{}", e),
                    };
                    println!(
                        "{}: records not matching: expected {}, found {}",
                        server,
                        settings.expected.data(),
                        rset,
                    );
                }
            }
        },
    )
}
