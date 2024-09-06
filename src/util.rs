use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    num::ParseIntError,
    str::FromStr,
};

use hickory_client::{op::ResponseCode, proto::error::ProtoError, rr};
use hickory_resolver::error::{ResolveError, ResolveErrorKind};

use crate::Resolver;

pub fn parse_comma_separated<T>(s: &str) -> Result<Vec<T>, T::Err>
where
    T: FromStr,
{
    s.split(',')
        .map(|part| part.parse())
        .collect::<Result<_, _>>()
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
        resolver: impl Resolver,
        default_port: u16,
    ) -> Result<SocketAddr, ResolveError> {
        match self {
            SocketName::HostName(name, port) => {
                let port = port.unwrap_or(default_port);
                let lookup = resolver.lookup_ip(name.clone()).await?;
                // TODO: how to choose from multiple addresses
                if let Some(ip) = lookup.iter().next() {
                    Ok(SocketAddr::new(ip, port))
                } else {
                    Err(ResolveErrorKind::NoRecordsFound {
                        query: Box::new(lookup.query().clone()),
                        soa: None,
                        negative_ttl: None,
                        response_code: ResponseCode::NXDomain,
                        trusted: false,
                    }
                    .into())
                }
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
