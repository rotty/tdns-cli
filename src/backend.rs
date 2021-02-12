/// An abstraction over different ways to do DNS queries.
use std::net::SocketAddr;

//use async_trait::async_trait;
use futures::{future::BoxFuture, FutureExt};
use tokio::net::{TcpStream, UdpSocket};
use trust_dns_client::{
    client::{AsyncClient, ClientFuture, ClientHandle},
    rr,
    tcp::TcpClientStream,
    udp::UdpClientStream,
};
use trust_dns_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    error::ResolveError,
    lookup, lookup_ip,
    proto::{error::ProtoError, xfer::dns_request::DnsRequestOptions},
    TokioAsyncResolver,
};

pub use tokio::runtime::Runtime;

pub type RuntimeHandle = tokio::runtime::Handle;

pub type LookupFuture = BoxFuture<'static, Result<lookup::Lookup, ResolveError>>;
pub type LookupIpFuture = BoxFuture<'static, Result<lookup_ip::LookupIp, ResolveError>>;
pub type LookupSoaFuture = BoxFuture<'static, Result<lookup::SoaLookup, ResolveError>>;
pub type LookupNsFuture = BoxFuture<'static, Result<lookup::NsLookup, ResolveError>>;

pub trait Resolver: Clone {
    fn lookup(&self, name: rr::Name, rtype: rr::RecordType) -> LookupFuture;
    fn lookup_ip(&self, host: rr::Name) -> LookupIpFuture;
    fn lookup_soa(&self, name: rr::Name) -> LookupSoaFuture;
    fn lookup_ns(&self, name: rr::Name) -> LookupNsFuture;
}

impl Resolver for TokioAsyncResolver {
    fn lookup(&self, name: rr::Name, rtype: rr::RecordType) -> LookupFuture {
        TokioAsyncResolver::lookup(self, name, rtype, DnsRequestOptions::default()).boxed()
    }

    fn lookup_ip(&self, host: rr::Name) -> LookupIpFuture {
        let resolver = self.clone();
        Box::pin(async move { TokioAsyncResolver::lookup_ip(&resolver, host).await })
    }

    fn lookup_soa(&self, name: rr::Name) -> LookupSoaFuture {
        let resolver = self.clone();
        Box::pin(async move { TokioAsyncResolver::soa_lookup(&resolver, name).await })
    }

    fn lookup_ns(&self, name: rr::Name) -> LookupNsFuture {
        let resolver = self.clone();
        Box::pin(async move { TokioAsyncResolver::ns_lookup(&resolver, name).await })
    }
}

pub trait Backend: Clone {
    type Client: ClientHandle;
    type Resolver: Resolver;
    fn open(&mut self, runtime: &Runtime, addr: SocketAddr) -> Result<Self::Client, ProtoError>;
    fn open_resolver(&mut self, addr: SocketAddr) -> Result<Self::Resolver, ResolveError>;
    fn open_system_resolver(&mut self) -> Result<Self::Resolver, ResolveError>;
}

#[derive(Debug, Clone)]
pub struct TcpBackend;

impl Backend for TcpBackend {
    type Client = AsyncClient;
    type Resolver = TokioAsyncResolver;

    fn open(&mut self, runtime: &Runtime, addr: SocketAddr) -> Result<Self::Client, ProtoError> {
        use trust_dns_resolver::proto::iocompat::AsyncIoTokioAsStd;
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TcpStream>>::new(addr);
        let connect = AsyncClient::new(Box::new(stream), sender, None);
        let (client, bg) = runtime.block_on(connect)?; // TODO: should not block
        runtime.spawn(bg);
        Ok(client)
    }

    fn open_resolver(&mut self, addr: SocketAddr) -> Result<Self::Resolver, ResolveError> {
        make_resolver(addr, Protocol::Tcp)
    }

    fn open_system_resolver(&mut self) -> Result<Self::Resolver, ResolveError> {
        TokioAsyncResolver::tokio_from_system_conf()
    }
}

#[derive(Debug, Clone)]
pub struct UdpBackend;

impl Backend for UdpBackend {
    type Client = AsyncClient;
    type Resolver = TokioAsyncResolver;

    fn open(&mut self, runtime: &Runtime, addr: SocketAddr) -> Result<Self::Client, ProtoError> {
        let stream = UdpClientStream::<UdpSocket>::new(addr);
        let (client, bg) = runtime.block_on(ClientFuture::connect(stream))?; // TODO: should not block
        runtime.spawn(bg);
        Ok(client)
    }

    fn open_resolver(&mut self, addr: SocketAddr) -> Result<Self::Resolver, ResolveError> {
        make_resolver(addr, Protocol::Udp)
    }

    fn open_system_resolver(&mut self) -> Result<Self::Resolver, ResolveError> {
        TokioAsyncResolver::tokio_from_system_conf()
    }
}

fn make_resolver(addr: SocketAddr, protocol: Protocol) -> Result<TokioAsyncResolver, ResolveError> {
    let mut config = ResolverConfig::new();
    config.add_name_server(NameServerConfig {
        socket_addr: addr,
        protocol,
        tls_dns_name: None,
        trust_nx_responses: true,
    });
    TokioAsyncResolver::tokio(config, ResolverOpts::default())
}
