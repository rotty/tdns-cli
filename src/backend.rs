/// An abstraction over different ways to do DNS queries.
use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::net::{TcpStream, UdpSocket};
use hickory_client::{
    client::{AsyncClient, ClientFuture, ClientHandle},
    rr,
    tcp::TcpClientStream,
    udp::UdpClientStream,
};
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    error::{ResolveError, ResolveResult},
    lookup, lookup_ip,
    proto::error::ProtoError,
    TokioAsyncResolver,
};

pub use tokio::runtime::Runtime;

pub type RuntimeHandle = tokio::runtime::Handle;

#[async_trait]
pub trait Resolver: Clone {
    async fn lookup(
        &self,
        name: rr::Name,
        rtype: rr::RecordType,
    ) -> Result<lookup::Lookup, ResolveError>;
    async fn lookup_ip(&self, host: rr::Name) -> ResolveResult<lookup_ip::LookupIp>;
    async fn lookup_soa(&self, name: rr::Name) -> ResolveResult<lookup::SoaLookup>;
    async fn lookup_ns(&self, name: rr::Name) -> ResolveResult<lookup::NsLookup>;
}

#[async_trait]
impl Resolver for TokioAsyncResolver {
    async fn lookup(&self, name: rr::Name, rtype: rr::RecordType) -> ResolveResult<lookup::Lookup> {
        TokioAsyncResolver::lookup(self, name, rtype).await
    }

    async fn lookup_ip(&self, host: rr::Name) -> ResolveResult<lookup_ip::LookupIp> {
        TokioAsyncResolver::lookup_ip(self, host).await
    }

    async fn lookup_soa(&self, name: rr::Name) -> ResolveResult<lookup::SoaLookup> {
        TokioAsyncResolver::soa_lookup(self, name).await
    }

    async fn lookup_ns(&self, name: rr::Name) -> ResolveResult<lookup::NsLookup> {
        TokioAsyncResolver::ns_lookup(self, name).await
    }
}

#[async_trait]
pub trait Backend: Clone {
    type Client: ClientHandle;
    type Resolver: Resolver;
    async fn open(
        &mut self,
        runtime: &Runtime,
        addr: SocketAddr,
    ) -> Result<Self::Client, ProtoError>;
    fn open_resolver(&mut self, addr: SocketAddr) -> Self::Resolver;
    fn open_system_resolver(&mut self) -> ResolveResult<Self::Resolver>;
}

#[derive(Debug, Clone)]
pub struct TcpBackend;

#[async_trait]
impl Backend for TcpBackend {
    type Client = AsyncClient;
    type Resolver = TokioAsyncResolver;

    async fn open(
        &mut self,
        runtime: &Runtime,
        addr: SocketAddr,
    ) -> Result<Self::Client, ProtoError> {
        use hickory_resolver::proto::iocompat::AsyncIoTokioAsStd;
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TcpStream>>::new(addr);
        let (client, bg) = AsyncClient::new(Box::new(stream), sender, None).await?;
        runtime.spawn(bg);
        Ok(client)
    }

    fn open_resolver(&mut self, addr: SocketAddr) -> Self::Resolver {
        make_resolver(addr, Protocol::Tcp)
    }

    fn open_system_resolver(&mut self) -> ResolveResult<Self::Resolver> {
        TokioAsyncResolver::tokio_from_system_conf()
    }
}

#[derive(Debug, Clone)]
pub struct UdpBackend;

#[async_trait]
impl Backend for UdpBackend {
    type Client = AsyncClient;
    type Resolver = TokioAsyncResolver;

    async fn open(
        &mut self,
        runtime: &Runtime,
        addr: SocketAddr,
    ) -> Result<Self::Client, ProtoError> {
        let stream = UdpClientStream::<UdpSocket>::new(addr);
        let (client, bg) = ClientFuture::connect(stream).await?;
        runtime.spawn(bg);
        Ok(client)
    }

    fn open_resolver(&mut self, addr: SocketAddr) -> Self::Resolver {
        make_resolver(addr, Protocol::Udp)
    }

    fn open_system_resolver(&mut self) -> ResolveResult<Self::Resolver> {
        TokioAsyncResolver::tokio_from_system_conf()
    }
}

fn make_resolver(addr: SocketAddr, protocol: Protocol) -> TokioAsyncResolver {
    let mut config = ResolverConfig::new();
    config.add_name_server(NameServerConfig {
        socket_addr: addr,
        protocol,
        tls_dns_name: None,
        trust_negative_responses: true,
        bind_addr: None,
    });
    TokioAsyncResolver::tokio(config, ResolverOpts::default())
}
