use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use anyhow::anyhow;
use async_trait::async_trait;
use futures::future;
use trust_dns_client::{
    op::update_message::UpdateMessage,
    proto::{
        error::ProtoError,
        op::{Message, OpCode, Query},
        rr,
        xfer::{DnsRequest, DnsResponse},
        DnsHandle,
    },
};
use trust_dns_resolver::{
    error::{ResolveError, ResolveErrorKind},
    lookup,
    lookup::Lookup,
    lookup_ip,
};

use tdns_cli::{Backend, Resolver, Runtime};

pub type Handle<T> = Arc<Mutex<T>>;
pub type FutureResult<T, E> = future::Ready<Result<T, E>>;

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

pub fn parse_rdata(rtype: &str, rdata: &str) -> anyhow::Result<rr::RData> {
    use rr::{rdata::SOA, RData};
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
                        name.parse()?,
                        0,
                        parse_rdata(rtype, rdata)?,
                    ))
                })
                .collect::<anyhow::Result<_>>()?,
        ))
    }
}

#[derive(Clone, Default)]
pub struct MockBackend {
    resolv_conf: Option<SocketAddr>,
    servers: HashMap<SocketAddr, Handle<Server>>,
}

impl MockBackend {
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
        self.servers.insert(addr, server);
    }

    fn open_client(&self, addr: SocketAddr) -> Client {
        let server = self
            .servers
            .get(&addr)
            .unwrap_or_else(|| panic!("no server for address {}", addr));
        Client(server.clone())
    }
}

#[async_trait]
impl Backend for MockBackend {
    type Client = Client;
    type Resolver = Client;
    async fn open(
        &mut self,
        _runtime: &Runtime,
        addr: SocketAddr,
    ) -> Result<Self::Client, ProtoError> {
        Ok(self.open_client(addr))
    }
    fn open_resolver(&mut self, addr: SocketAddr) -> Result<Self::Resolver, ResolveError> {
        Ok(self.open_client(addr))
    }
    fn open_system_resolver(&mut self) -> Result<Self::Resolver, ResolveError> {
        if let Some(addr) = self.resolv_conf {
            Ok(self.open_client(addr))
        } else {
            Err(ResolveErrorKind::Message("no system resolver address configured").into())
        }
    }
}

#[derive(Clone)]
pub struct Client(Arc<Mutex<Server>>);

impl Client {
    fn query(&self, query: Query) -> Result<DnsResponse, ProtoError> {
        let mut server = self.0.lock().unwrap();
        let mut message = Message::new();
        message.add_query(query);
        server.request(message.into())
    }
    fn lookup_base(&self, name: rr::Name, rtype: rr::RecordType) -> Result<Lookup, ResolveError> {
        let query = Query::query(name, rtype);
        self.query(query.clone())
            .map(|response| {
                Lookup::new_with_max_ttl(query, response.answers().iter().cloned().collect())
            })
            .map_err(Into::into)
    }
}

pub struct Server {
    zone: Handle<Zone>,
    query_log: Vec<DnsRequest>,
}

impl Server {
    pub fn zone(&self) -> Handle<Zone> {
        Arc::clone(&self.zone)
    }
    fn request(&mut self, request: DnsRequest) -> Result<DnsResponse, ProtoError> {
        self.query_log.push(request.clone());
        match request.op_code() {
            OpCode::Query => {
                let mut message = Message::new();
                let zone = self.zone.lock().unwrap();
                for query in request.queries() {
                    for record in zone.matches(query) {
                        message.add_answer(record);
                    }
                }
                Ok(message.into())
            }
            OpCode::Update => {
                let mut zone = self.zone.lock().unwrap();
                for update in request.updates() {
                    zone.update(update);
                }
                Ok(Message::new().into())
            }
            _ => unimplemented!(),
        }
    }
}

impl DnsHandle for Client {
    type Error = ProtoError;
    type Response = FutureResult<DnsResponse, ProtoError>;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> Self::Response {
        let mut server = self.0.lock().unwrap();
        future::ready(server.request(request.into()))
    }
}

#[async_trait]
impl Resolver for Client {
    async fn lookup(
        &self,
        name: rr::Name,
        rtype: rr::RecordType,
    ) -> Result<lookup::Lookup, ResolveError> {
        self.lookup_base(name, rtype)
    }
    async fn lookup_ip(&self, host: rr::Name) -> Result<lookup_ip::LookupIp, ResolveError> {
        // TODO: IPv6
        self.lookup_base(host, rr::RecordType::A).map(Into::into)
    }
    async fn lookup_soa(&self, name: rr::Name) -> Result<lookup::SoaLookup, ResolveError> {
        self.lookup_base(name, rr::RecordType::SOA).map(Into::into)
    }
    async fn lookup_ns(&self, name: rr::Name) -> Result<lookup::NsLookup, ResolveError> {
        self.lookup_base(name, rr::RecordType::NS).map(Into::into)
    }
}
