use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
};

use anyhow::anyhow;
use failure::ResultExt;
use futures::future::{self, FutureResult};
use trust_dns::{
    op::update_message::UpdateMessage,
    proto::{
        error::ProtoError,
        op::{Message, OpCode, Query},
        rr,
        xfer::{DnsRequest, DnsResponse},
        DnsHandle,
    },
};

use tdns_cli::{DnsOpen, RuntimeHandle};

pub type Handle<T> = Arc<Mutex<T>>;

#[derive(Debug, Clone)]
pub struct Zone(Vec<rr::Record>);

impl Zone {
    fn matches(&self, query: &Query) -> impl Iterator<Item = rr::Record> + '_ {
        let query = query.clone();
        self.0
            .iter()
            .filter(move |r| r.name() == query.name())
            .cloned()
    }
    pub fn update(&mut self, update: &rr::Record) {
        if update.dns_class() == rr::DNSClass::NONE {
            self.0
                .retain(|r| r.record_type() != update.record_type() && r.name() != update.name());
        } else if let Some(record) = self
            .0
            .iter_mut()
            .find(|r| r.record_type() == update.record_type() && r.name() == update.name())
        {
            record.set_rdata(update.rdata().clone());
        }
    }
}

fn parse_compat<T, E>(s: &str) -> Result<T, anyhow::Error>
where
    T: FromStr<Err = E>,
    E: failure::Fail,
{
    Ok(s.parse::<T>().compat()?)
}

pub fn parse_rdata(rtype: &str, rdata: &str) -> Result<rr::RData, anyhow::Error> {
    use rr::{rdata::SOA, RData};
    match rtype {
        "A" => Ok(RData::A(parse_compat(rdata)?)),
        "AAAA" => Ok(RData::AAAA(parse_compat(rdata)?)),
        "NS" => Ok(RData::NS(parse_compat(rdata)?)),
        "SOA" => {
            let parts: Vec<_> = rdata.split(' ').collect();
            // This quite ugly -- is there a better way?
            Ok(RData::SOA(SOA::new(
                parse_compat(parts[0])?,
                parse_compat(parts[1])?,
                parse_compat(parts[2])?,
                parse_compat(parts[3])?,
                parse_compat(parts[4])?,
                parse_compat(parts[5])?,
                parse_compat(parts[6])?,
            )))
        }
        _ => Err(anyhow!("unsupported record type: {}", rtype)),
    }
}

pub type ZoneEntries<'a> = &'a [(&'a str, &'a str, &'a str)];

impl<'a> TryFrom<ZoneEntries<'a>> for Zone {
    type Error = anyhow::Error;

    fn try_from(entries: ZoneEntries) -> Result<Self, Self::Error> {
        Ok(Zone(
            entries
                .iter()
                .map(|(name, rtype, rdata)| {
                    Ok(rr::Record::from_rdata(
                        parse_compat(name)?,
                        0,
                        parse_rdata(rtype, rdata)?,
                    ))
                })
                .collect::<Result<_, anyhow::Error>>()?,
        ))
    }
}

#[derive(Clone, Default)]
pub struct Open {
    servers: HashMap<SocketAddr, Handle<Server>>,
}

impl Open {
    pub fn add_server<T>(&mut self, addr: SocketAddr, zone: T) -> Result<Handle<Server>, T::Error>
    where
        T: TryInto<Zone>,
    {
        let server = Arc::new(Mutex::new(Server {
            zone: Arc::new(Mutex::new(zone.try_into()?)),
            query_log: Default::default(),
        }));
        self.servers.insert(addr, server.clone());
        Ok(server)
    }

    pub fn add_shared(&mut self, addr: SocketAddr, zone: Handle<Zone>) {
        let server = Arc::new(Mutex::new(Server {
            zone,
            query_log: Default::default(),
        }));
        self.servers.insert(addr, server.clone());
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

pub struct Server {
    zone: Handle<Zone>,
    query_log: Vec<DnsRequest>,
}

impl Server {
    pub fn zone(&self) -> Handle<Zone> {
        Arc::clone(&self.zone)
    }
}

impl DnsHandle for Client {
    type Response = FutureResult<DnsResponse, ProtoError>;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> Self::Response {
        let mut server = self.0.lock().unwrap();
        let request = request.into();
        server.query_log.push(request.clone());
        match request.op_code() {
            OpCode::Query => {
                let mut message = Message::new();
                let zone = server.zone.lock().unwrap();
                for query in request.queries() {
                    for record in zone.matches(query) {
                        message.add_answer(record);
                    }
                }
                future::ok(message.into())
            }
            OpCode::Update => {
                let mut zone = server.zone.lock().unwrap();
                for update in request.updates() {
                    zone.update(update);
                }
                future::ok(Message::new().into())
            }
            _ => unimplemented!(),
        }
    }
}
