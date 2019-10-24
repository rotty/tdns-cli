use std::{
    convert::TryFrom,
    fmt,
    net::{IpAddr, SocketAddr},
    rc::Rc,
    time::{Duration, Instant},
};

use failure::format_err;
use futures::stream::{FuturesUnordered, TryStreamExt};
use tokio::timer::{delay, Timeout};
use trust_dns_client::{
    op::{Message, Query},
    proto::xfer::{DnsHandle, DnsRequestOptions},
    rr,
};

use crate::{
    record::{RecordSet, RsData},
    tsig, update_message,
    util::{self, SocketName},
    Backend, Resolver, RuntimeHandle,
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

pub async fn perform_update<D>(
    runtime: RuntimeHandle,
    mut dns: D,
    resolver: D::Resolver,
    options: Update,
) -> Result<(), failure::Error>
where
    D: Backend,
    D::Resolver: 'static,
{
    let message = options.get_update()?;
    let master = if let Some(sockname) = options.server {
        sockname.resolve(resolver, 53).await?
    } else if let Some(soa) = resolver
        .lookup_soa(options.zone.clone())
        .await?
        .iter()
        .next()
    {
        util::SocketName::HostName(soa.mname().clone(), None)
            .resolve(resolver, 53)
            .await?
    } else {
        return Err(format_err!("SOA record for {} not found", options.zone));
    };
    let mut server = dns.open(runtime.clone(), master);
    // TODO: probably should check response
    server.send(message).await?;
    Ok(())
}

pub async fn monitor_update<D>(
    runtime: RuntimeHandle,
    dns: D,
    resolver: D::Resolver,
    options: Monitor,
) -> Result<(), failure::Error>
where
    D: Backend,
{
    let options = Rc::new(options);
    let authorative = resolver.lookup_ns(options.zone.clone()).await?;
    match Timeout::new(
        poll_for_update(runtime, dns, resolver, authorative, Rc::clone(&options)),
        options.timeout,
    )
    .await?
    {
        Ok(_) => Ok(()),
        Err(_) => Err(format_err!(
            "timeout; update not complete within {}ms",
            options.timeout.as_millis()
        )),
    }
}

async fn poll_for_update<D, I>(
    runtime: RuntimeHandle,
    dns: D,
    resolver: D::Resolver,
    authorative: I,
    options: Rc<Monitor>,
) -> Result<(), failure::Error>
where
    I: IntoIterator<Item = rr::Name>,
    D: Backend,
{
    let results: FuturesUnordered<_> = authorative
        .into_iter()
        .map(move |server_name| {
            poll_server(
                runtime.clone(),
                dns.clone(),
                resolver.clone(),
                server_name.clone(),
                Rc::clone(&options),
            )
        })
        .collect();
    results.try_collect().await?;
    Ok(())
}

async fn poll_server<D>(
    runtime: RuntimeHandle,
    mut dns: D,
    resolver: D::Resolver,
    server_name: rr::Name,
    options: Rc<Monitor>,
) -> Result<(), failure::Error>
where
    D: Backend,
{
    let ip = resolver
        .lookup_ip(server_name.clone())
        .await?
        .iter()
        .next()
        .ok_or_else(|| format_err!("could not resolve {}", &server_name))?;
    if options.exclude.contains(&ip) {
        return Ok(());
    }
    let mut server = dns.open(runtime.clone(), SocketAddr::new(ip, 53));
    let server_name = server_name.clone();
    let options = Rc::clone(&options);
    let query = options.get_query();
    loop {
        if let Ok(response) = server
            .lookup(query.clone(), DnsRequestOptions::default())
            .await
        {
            let answers = response.answers();
            let hit = options.expectation.satisfied_by(answers);
            if options.verbose {
                if hit {
                    println!("{}: match found", &server_name);
                } else {
                    let rset = match RecordSet::try_from(answers) {
                        Ok(rs) => format!("{}", rs.data()),
                        Err(e) => format!("{}", e),
                    };
                    println!(
                        "{}: records not matching: {}, found {}",
                        server_name, options.expectation, rset,
                    );
                }
            }
            if hit {
                return Ok(());
            } else {
                let when = Instant::now() + options.interval;
                delay(when).await;
            }
        }
    }
}
