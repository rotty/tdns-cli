use std::{
    fmt, fs,
    net::{IpAddr, SocketAddr},
    num::ParseIntError,
    str::FromStr,
};

use failure::format_err;
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
    pub async fn resolve(
        &self,
        resolver: impl DnsHandle,
        default_port: u16,
    ) -> Result<SocketAddr, failure::Error> {
        match self {
            SocketName::HostName(name, port) => {
                let port = port.unwrap_or(default_port);
                let ip = resolve_ip(resolver, name.clone()).await?;
                Ok(SocketAddr::new(ip, port))
            }
            SocketName::IpAddr(addr) => Ok(SocketAddr::new(*addr, default_port)),
            SocketName::SocketAddr(addr) => Ok(*addr),
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

pub async fn dns_query(
    mut recursor: impl ClientHandle,
    query: Query,
) -> Result<DnsResponse, failure::Error> {
    const MAX_TRIES: usize = 3;
    let mut count = 1;
    loop {
        match recursor.lookup(query.clone(), Default::default()).await {
            Ok(addrs) => return Ok(addrs),
            Err(e) if count == MAX_TRIES => {
                return Err(format_err!(
                    "could not resolve server name '{}' (max retries reached): {}",
                    query.name(),
                    e
                ))
            }
            Err(_) => {}
        }
        count += 1;
    }
}

pub async fn query_ip_addr(
    recursor: impl ClientHandle,
    name: rr::Name,
) -> Result<Vec<IpAddr>, failure::Error> {
    // FIXME: IPv6
    let response = dns_query(recursor, Query::query(name, RecordType::A)).await?;
    Ok(response
        .answers()
        .iter()
        .filter_map(|r| r.rdata().to_ip_addr())
        .collect())
}

pub async fn get_ns_records<R>(recursor: R, domain: rr::Name) -> Result<Vec<Record>, failure::Error>
where
    R: ClientHandle,
{
    let response = dns_query(recursor, Query::query(domain, RecordType::NS)).await?;
    Ok(response.answers().to_vec())
}

pub async fn resolve_ip(
    recursor: impl ClientHandle,
    server_name: rr::Name,
) -> Result<IpAddr, failure::Error> {
    let addrs = query_ip_addr(recursor.clone(), server_name.clone()).await?;
    // TODO: handle multiple addresses
    if let Some(addr) = addrs.first().cloned() {
        Ok(addr)
    } else {
        Err(format_err!(
            "could not resolve server '{}': no addresses found",
            server_name
        ))
    }
}
