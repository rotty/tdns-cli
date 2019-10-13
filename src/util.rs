use std::{
    fmt, fs,
    net::{IpAddr, SocketAddr},
    num::ParseIntError,
    str::FromStr,
};

use failure::format_err;
use futures::{
    future::{self, Either},
    Future,
};
use trust_dns::{
    client::ClientHandle,
    op::DnsResponse,
    proto::{error::ProtoError, op::query::Query, xfer::DnsHandle},
    rr::{self, Record, RecordType},
};

pub fn parse_comma_separated<T>(s: &str) -> Result<Vec<T>, T::Err>
where
    T: FromStr,
{
    Ok(s.split(',')
        .map(|part| part.parse())
        .collect::<Result<_, _>>()?)
}

/// A potential unresolved host name, with an optional port number.
#[derive(Debug, Clone)]
pub enum SocketName {
    HostName(rr::Name, Option<u16>),
    SocketAddr(SocketAddr),
    IpAddr(IpAddr),
}

impl SocketName {
    pub fn resolve(
        &self,
        resolver: impl DnsHandle,
        default_port: u16,
    ) -> impl Future<Item = SocketAddr, Error = failure::Error> {
        match self {
            SocketName::HostName(name, port) => {
                let port = port.unwrap_or(default_port);
                Either::A(
                    resolve_ip(resolver, name.clone()).map(move |ip| SocketAddr::new(ip, port)),
                )
            }
            SocketName::IpAddr(addr) => Either::B(future::ok(SocketAddr::new(*addr, default_port))),
            SocketName::SocketAddr(addr) => Either::B(future::ok(*addr)),
        }
    }
}

impl FromStr for SocketName {
    type Err = ParseSocketNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse()
            .map(SocketName::SocketAddr)
            .or_else(|_| s.parse().map(SocketName::IpAddr))
            .or_else(|_| {
                let parts: Vec<_> = s.split(':').collect();
                match parts.len() {
                    1 => Ok(SocketName::HostName(
                        parts[0].parse().map_err(ParseSocketNameError::Name)?,
                        None,
                    )),
                    2 => Ok(SocketName::HostName(
                        parts[0].parse().map_err(ParseSocketNameError::Name)?,
                        Some(parts[1].parse().map_err(ParseSocketNameError::Port)?),
                    )),
                    _ => Err(ParseSocketNameError::Invalid),
                }
            })
    }
}

impl fmt::Display for ParseSocketNameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseSocketNameError::*;
        match self {
            Invalid => write!(
                f,
                "invalid socket name, expected IP, IP:PORT, HOST, or HOST:PORT"
            ),
            Name(e) => write!(f, "invalid host name: {}", e),
            Port(e) => write!(f, "invalid port: {}", e),
        }
    }
}

impl std::error::Error for ParseSocketNameError {}

#[derive(Debug)]
pub enum ParseSocketNameError {
    Invalid,
    Name(ProtoError),
    Port(ParseIntError),
}

pub fn get_system_resolver() -> Option<SocketAddr> {
    use resolv_conf::{Config, ScopedIp};
    let resolv_conf = fs::read("/etc/resolv.conf").ok()?;
    let config = Config::parse(&resolv_conf).ok()?;
    config.nameservers.iter().find_map(|scoped| match scoped {
        ScopedIp::V4(v4) => Some(SocketAddr::new(v4.clone().into(), 53)),
        ScopedIp::V6(v6, _) => Some(SocketAddr::new(v6.clone().into(), 53)),
    })
}

pub fn dns_query(
    mut recursor: impl ClientHandle,
    query: Query,
) -> impl Future<Item = DnsResponse, Error = failure::Error> {
    use future::Loop;
    const MAX_TRIES: usize = 3;
    future::loop_fn(0, move |count| {
        let run_query = recursor.lookup(query.clone(), Default::default());
        let name = query.name().clone();
        run_query.then(move |result| match result {
            Ok(addrs) => future::ok(Loop::Break(addrs)),
            Err(_) if count < MAX_TRIES => future::ok(Loop::Continue(count + 1)),
            Err(e) => future::err(format_err!(
                "could not resolve server name '{}' (max retries reached): {}",
                name,
                e
            )),
        })
    })
}

pub fn query_ip_addr(
    recursor: impl ClientHandle,
    name: rr::Name,
) -> impl Future<Item = Vec<IpAddr>, Error = failure::Error> + 'static {
    // FIXME: IPv6
    dns_query(recursor, Query::query(name, RecordType::A)).map(|response| {
        response
            .answers()
            .iter()
            .filter_map(|r| r.rdata().to_ip_addr())
            .collect()
    })
}

pub fn get_ns_records<R>(
    recursor: R,
    domain: rr::Name,
) -> impl Future<Item = Vec<Record>, Error = failure::Error>
where
    R: ClientHandle,
{
    dns_query(recursor, Query::query(domain, RecordType::NS))
        .map(|response| response.answers().to_vec())
}

pub fn resolve_ip(
    recursor: impl ClientHandle,
    server_name: rr::Name,
) -> impl Future<Item = IpAddr, Error = failure::Error> {
    query_ip_addr(recursor.clone(), server_name.clone()).and_then(move |addrs| {
        // TODO: handle multiple addresses
        if let Some(addr) = addrs.first().cloned() {
            Ok(addr)
        } else {
            Err(format_err!(
                "could not resolve server '{}': no addresses found",
                server_name
            ))
        }
    })
}
