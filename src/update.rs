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
    op::{DnsResponse, Message, Query},
    proto::xfer::{DnsHandle, DnsRequestOptions},
    rr::{self, Record},
};

use crate::{
    record::{RecordSet, RsData},
    tsig, update_message,
    util::{self, SocketName},
    DnsOpen, RuntimeHandle,
};

#[derive(Debug, Clone)]
pub struct Update {
    pub zone: rr::Name,
    pub server: Option<SocketName>,
    pub operation: Operation,
    pub tsig_key: Option<tsig::Key>,
    pub ttl: u32,
}

impl Update {
    pub fn get_update(&self) -> Result<Message, tsig::Error> {
        let ttl = self.ttl;
        let mut message = match &self.operation {
            Operation::Create(rset) => {
                update_message::create(rset.to_rrset(ttl), self.zone.clone())
            }
            Operation::Append(rset) => {
                update_message::append(rset.to_rrset(ttl), self.zone.clone(), false)
            }
            Operation::Delete(rset) => {
                if rset.is_empty() {
                    let record = rr::Record::with(rset.name().clone(), rset.record_type(), ttl);
                    update_message::delete_rrset(record, self.zone.clone())
                } else {
                    update_message::delete_by_rdata(rset.to_rrset(ttl), self.zone.clone())
                }
            }
            Operation::DeleteAll(name) => {
                update_message::delete_all(name.clone(), self.zone.clone(), rr::DNSClass::IN)
            }
        };
        if let Some(key) = &self.tsig_key {
            tsig::add_signature(&mut message, key)?;
        }
        Ok(message)
    }
}

#[derive(Debug, Clone)]
pub struct Monitor {
    pub zone: rr::Name,
    pub entry: rr::Name,
    pub interval: Duration,
    pub timeout: Duration,
    pub verbose: bool,
    pub exclude: Vec<IpAddr>,
    pub expectation: Expectation,
}

impl Monitor {
    fn get_query(&self) -> Query {
        Query::query(self.entry.clone(), self.expectation.record_type())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Operation {
    Create(RecordSet),
    Append(RecordSet),
    Delete(RecordSet),
    DeleteAll(rr::Name),
}

impl Operation {
    pub fn create(name: rr::Name, data: RsData) -> Self {
        Operation::Create(RecordSet::new(name, data))
    }

    pub fn delete(name: rr::Name, data: RsData) -> Self {
        Operation::Delete(RecordSet::new(name, data))
    }
}

#[derive(Debug, Clone)]
pub enum Expectation {
    Is(RecordSet),
    Contains(RecordSet),
    Empty(rr::RecordType),
    NotAny(RecordSet),
}

impl Expectation {
    pub fn record_type(&self) -> rr::RecordType {
        match self {
            Expectation::Is(rset) => rset.record_type(),
            Expectation::Contains(rset) => rset.record_type(),
            Expectation::NotAny(rset) => rset.record_type(),
            Expectation::Empty(rtype) => *rtype,
        }
    }

    pub fn satisfied_by(&self, rrs: &[rr::Record]) -> bool {
        match self {
            Expectation::Is(other) => {
                let rset = match RecordSet::try_from(rrs) {
                    Err(_) => return false,
                    Ok(rs) => rs,
                };
                rset == *other
            }
            Expectation::Contains(other) => {
                let rset = match RecordSet::try_from(rrs) {
                    Err(_) => return false,
                    Ok(rs) => rs,
                };
                other.is_subset(&rset)
            }
            Expectation::Empty(_) => rrs.is_empty(),
            Expectation::NotAny(other) => {
                if rrs.is_empty() {
                    return true;
                }
                let rset = match RecordSet::try_from(rrs) {
                    Err(_) => return false,
                    Ok(rs) => rs,
                };
                !other.iter_data().any(|r| rset.contains(&r))
            }
        }
    }
}

impl fmt::Display for Expectation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Expectation::Is(rset) => write!(f, "expected {}", rset.data()),
            Expectation::Contains(rset) => write!(f, "expected at least {} records", rset.data()),
            Expectation::Empty(rtype) => write!(f, "expected no {} records", rtype),
            Expectation::NotAny(rset) => write!(f, "expected none of {}", rset),
        }
    }
}

pub fn perform_update<D>(
    runtime: RuntimeHandle,
    mut dns: D,
    mut resolver: D::Client,
    options: Update,
) -> Result<impl Future<Item = (), Error = failure::Error>, failure::Error>
where
    D: DnsOpen,
{
    let message = options.get_update()?;
    let get_master = if let Some(sockname) = options.server {
        Box::new(sockname.resolve(resolver, 53))
            as Box<dyn Future<Item = SocketAddr, Error = failure::Error>>
    } else {
        let get_soa = resolver
            .query(options.zone.clone(), rr::DNSClass::IN, rr::RecordType::SOA)
            .map_err(failure::Error::from);
        let settings = options.clone();
        let resolver = resolver.clone();
        let resolve = get_soa.and_then(move |response| {
            if let Some(soa) = response
                .answers()
                .first()
                .and_then(|rr| rr.rdata().as_soa())
            {
                Either::A(
                    util::SocketName::HostName(soa.mname().clone(), None).resolve(resolver, 53),
                )
            } else {
                Either::B(future::err(format_err!(
                    "SOA record for {} not found",
                    settings.zone
                )))
            }
        });
        Box::new(resolve)
    };
    let update = get_master
        .and_then(move |master| {
            let mut server = dns.open(runtime.clone(), master);
            server.send(message).map_err(Into::into)
        })
        .map(|_| ()); // TODO: probably should check response
    Ok(update)
}

pub fn monitor_update<D>(
    runtime: RuntimeHandle,
    dns: D,
    resolver: D::Client,
    options: Monitor,
) -> impl Future<Item = (), Error = failure::Error>
where
    D: DnsOpen,
{
    let options = Rc::new(options);
    let get_authorative =
        util::get_ns_records(resolver.clone(), options.zone.clone()).map_err(failure::Error::from);
    let poll_servers = {
        let options = Rc::clone(&options);
        get_authorative.and_then(move |authorative| {
            let names = authorative
                .into_iter()
                .filter_map(|r| r.rdata().as_ns().cloned());
            poll_for_update(runtime, dns, resolver, names, options)
        })
    };
    poll_servers
        .timeout(options.timeout)
        .map_err(|e| {
            e.into_inner().unwrap_or_else(move || {
                format_err!(
                    "timeout; update not complete within {}ms",
                    options.timeout.as_millis()
                )
            })
        })
        .map(|_| ())
}

fn poll_for_update<D, I>(
    runtime: RuntimeHandle,
    dns: D,
    resolver: D::Client,
    authorative: I,
    options: Rc<Monitor>,
) -> impl Future<Item = (), Error = failure::Error>
where
    I: IntoIterator<Item = rr::Name>,
    D: DnsOpen,
{
    future::join_all(authorative.into_iter().map(move |server_name| {
        let handle = runtime.clone();
        let server_name = server_name.clone();
        let inner_options = Rc::clone(&options);
        let mut dns = dns.clone();
        let resolve = util::resolve_ip(resolver.clone(), server_name.clone()).map(move |ip| {
            if inner_options.exclude.contains(&ip) {
                None
            } else {
                Some(dns.open(handle.clone(), SocketAddr::new(ip, 53)))
            }
        });
        let server_name = server_name.clone();
        let options = Rc::clone(&options);
        resolve.and_then(move |maybe_server| match maybe_server {
            None => Either::A(future::ok(())),
            Some(server) => Either::B(poll_server(server.clone(), server_name, options)),
        })
    }))
    .map(|_| ())
}

fn poll_entries<F>(
    mut server: impl ClientHandle,
    server_name: rr::Name,
    settings: Rc<Monitor>,
    report: F,
) -> impl Future<Item = (), Error = failure::Error>
where
    F: Fn(&rr::Name, &[Record], bool) + 'static,
{
    use future::Loop;
    future::loop_fn(report, move |report| {
        let server_name = server_name.clone();
        let settings = Rc::clone(&settings);
        let query = settings.get_query();
        server
            .lookup(query, DnsRequestOptions::default())
            .map_err(failure::Error::from)
            .and_then(move |response: DnsResponse| {
                let answers = response.answers();
                let hit = settings.expectation.satisfied_by(answers);
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
    settings: Rc<Monitor>,
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
                        server, settings.expectation, rset,
                    );
                }
            }
        },
    )
}
