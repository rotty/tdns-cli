use std::{
    convert::TryFrom,
    fmt,
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
    op::{update_message, DnsResponse, Message},
    proto::xfer::DnsHandle,
    rr::{self, Record},
};

use crate::{
    record::{RecordSet, RsData},
    util, DnsOpen, RuntimeHandle,
};

#[derive(Debug, Clone)]
pub struct Settings {
    pub resolver: SocketAddr,
    pub rset: RecordSet,
    pub zone: rr::Name,
    pub entry: rr::Name,
    pub interval: Duration,
    pub timeout: Duration,
    pub verbose: bool,
    pub exclude: Vec<IpAddr>,
    pub operation: Operation,
    pub monitor: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            resolver: "127.0.0.1:53".parse().unwrap(),
            rset: RecordSet::new(Default::default(), RsData::A(Default::default())),
            zone: Default::default(),
            entry: Default::default(),
            interval: Default::default(),
            timeout: Default::default(),
            verbose: Default::default(),
            exclude: Default::default(),
            operation: Operation::Create,
            monitor: true,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum Operation {
    None,
    Create,
    Delete,
}

#[derive(Debug)]
pub enum Expectation {
    Is(RecordSet),
    Empty(rr::RecordType),
}

impl fmt::Display for Expectation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Expectation::Is(rset) => write!(f, "expected {}", rset.data()),
            Expectation::Empty(rtype) => write!(f, "expected no {} records", rtype),
        }
    }
}

impl Settings {
    pub fn get_rrset(&self) -> rr::RecordSet {
        let mut rrset = rr::RecordSet::new(&self.entry, self.rset.record_type(), 0);
        for data in self.rset.iter_data() {
            rrset.add_rdata(data);
        }
        rrset
    }

    pub fn get_update(&self) -> Option<Message> {
        let message = match self.operation {
            Operation::None => return None,
            Operation::Create => update_message::create(self.get_rrset(), self.zone.clone()),
            Operation::Delete => {
                update_message::delete_by_rdata(self.get_rrset(), self.zone.clone())
            }
        };
        Some(message)
    }

    pub fn satisfied_by(&self, rrs: &[rr::Record]) -> bool {
        match self.operation {
            Operation::None | Operation::Create => {
                let rset = match RecordSet::try_from(rrs) {
                    Err(_) => return false,
                    Ok(rs) => rs,
                };
                rset == self.rset
            }
            Operation::Delete => rrs.is_empty(),
        }
    }

    pub fn expectation(&self) -> Expectation {
        match self.operation {
            Operation::None | Operation::Create => Expectation::Is(self.rset.clone()),
            Operation::Delete => Expectation::Empty(self.rset.record_type()),
        }
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
        let op = self.clone().perform_update();
        let this = self.clone();
        if self.settings.monitor {
            Box::new(op.and_then(|_| this.wait_for_update()))
        } else {
            Box::new(op)
        }
    }

    fn perform_update(mut self: Self) -> impl Future<Item = (), Error = failure::Error> {
        let message = match self.settings.get_update() {
            Some(message) => message,
            None => return Either::A(future::ok(())),
        };
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
        let update = get_master
            .and_then(move |master| {
                let mut server = this
                    .dns
                    .open(this.runtime.clone(), SocketAddr::new(master, 53));
                server.send(message).map_err(Into::into)
            })
            .map(|_| ()); // TODO: probably should check response
        Either::B(update)
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
                settings.rset.dns_class(),
                settings.rset.record_type(),
            )
            .map_err(failure::Error::from)
            .and_then(move |response: DnsResponse| {
                let answers = response.answers();
                let hit = settings.satisfied_by(answers);
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
                        "{}: records not matching: {}, found {}",
                        server,
                        settings.expectation(),
                        rset,
                    );
                }
            }
        },
    )
}
