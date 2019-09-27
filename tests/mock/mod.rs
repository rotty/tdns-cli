use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use failure::format_err;
use futures::future::{self, FutureResult};
use trust_dns::proto::{
    error::ProtoError,
    op::{Message, Query},
    rr,
    xfer::{DnsRequest, DnsResponse},
    DnsHandle,
};

use tdns_update::{DnsOpen, RuntimeHandle};

#[derive(Debug, Clone)]
pub struct Zone(Vec<rr::Record>);

impl Zone {
    fn matches(&self, query: &Query) -> impl Iterator<Item = rr::Record> + '_ {
        let query = query.clone();
        self.0.iter().filter(move |r| r.name() == query.name()).cloned()
    }
}

fn parse_rdata(rtype: &str, rdata: &str) -> Result<rr::RData, failure::Error> {
    use rr::{RData, rdata::SOA};
    match rtype {
        "A" => Ok(RData::A(rdata.parse()?)),
        "AAAA" => Ok(RData::AAAA(rdata.parse()?)),
        "NS" => Ok(RData::NS(rdata.parse()?)),
        "SOA" => {
            let parts: Vec<_> = rdata.split(' ').collect();
            // This quite ugly -- is there a better way?
            Ok(RData::SOA(SOA::new(
                parts[0].parse()?,
                parts[1].parse()?,
                parts[2].parse()?,
                parts[3].parse()?,
                parts[4].parse()?,
                parts[5].parse()?,
                parts[6].parse()?,
            )))
        }
        _ => Err(format_err!("unsupported record type: {}", rtype)),
    }
}

impl TryFrom<&[(&str, &str, &str)]> for Zone {
    type Error = failure::Error;

    fn try_from(entries: &[(&str, &str, &str)]) -> Result<Self, Self::Error> {
        Ok(Zone(
            entries
                .iter()
                .map(|(name, rtype, rdata)| {
                    Ok(rr::Record::from_rdata(
                        name.parse()?,
                        0,
                        parse_rdata(rtype, rdata)?,
                    ))
                })
                .collect::<Result<_, failure::Error>>()?,
        ))
    }
}

#[derive(Clone)]
pub struct Open {
    servers: HashMap<SocketAddr, Arc<Mutex<Server>>>,
}

impl Open {
    pub fn new<I, T>(servers: I) -> Result<Self, T::Error>
    where
        I: IntoIterator<Item = (SocketAddr, T)>,
        T: TryInto<Zone>,
    {
        Ok(Open {
            servers: servers
                .into_iter()
                .map(|(addr, records)| {
                    Ok((
                        addr,
                        Arc::new(Mutex::new(Server {
                            zone: records.try_into()?,
                            query_log: Default::default(),
                        })),
                    ))
                })
                .collect::<Result<_, _>>()?,
        })
    }
}

impl DnsOpen for Open {
    type Client = Client;
    fn open(&mut self, _runtime: RuntimeHandle, addr: SocketAddr) -> Self::Client {
        let server = self
            .servers
            .get(&addr)
            .unwrap_or_else(|| panic!("no server for address {}", addr));
        Client(server.clone())
    }
}

#[derive(Clone)]
pub struct Client(Arc<Mutex<Server>>);

struct Server {
    zone: Zone,
    query_log: Vec<DnsRequest>,
}

impl DnsHandle for Client {
    type Response = FutureResult<DnsResponse, ProtoError>;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> Self::Response {
        let mut server = self.0.lock().unwrap();
        let request = request.into();
        server.query_log.push(request.clone());
        let mut message = Message::new();
        for query in request.queries() {
            for record in server.zone.matches(query) {
                message.add_answer(record);
            }
        }
        future::ok(message.into())
    }
}
