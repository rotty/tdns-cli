/// An abstraction over different ways to do DNS queries.
use std::net::SocketAddr;

use async_trait::async_trait;
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

#[async_trait]
pub trait Resolver: Clone {
    async fn lookup(
        &self,
        name: rr::Name,
        rtype: rr::RecordType,
    ) -> Result<lookup::Lookup, ResolveError>;
    async fn lookup_ip(&self, host: rr::Name) -> Result<lookup_ip::LookupIp, ResolveError>;
    async fn lookup_soa(&self, name: rr::Name) -> Result<lookup::SoaLookup, ResolveError>;
    async fn lookup_ns(&self, name: rr::Name) -> Result<lookup::NsLookup, ResolveError>;
}

#[async_trait]
impl Resolver for TokioAsyncResolver {
    async fn lookup(
        &self,
        name: rr::Name,
        rtype: rr::RecordType,
    ) -> Result<lookup::Lookup, ResolveError> {
        TokioAsyncResolver::lookup(self, name, rtype, DnsRequestOptions::default()).await
    }

    async fn lookup_ip(&self, host: rr::Name) -> Result<lookup_ip::LookupIp, ResolveError> {
        TokioAsyncResolver::lookup_ip(self, host).await
    }

    async fn lookup_soa(&self, name: rr::Name) -> Result<lookup::SoaLookup, ResolveError> {
        TokioAsyncResolver::soa_lookup(self, name).await
    }

    async fn lookup_ns(&self, name: rr::Name) -> Result<lookup::NsLookup, ResolveError> {
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
    fn open_resolver(&mut self, addr: SocketAddr) -> Result<Self::Resolver, ResolveError>;
    fn open_system_resolver(&mut self) -> Result<Self::Resolver, ResolveError>;
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
        use trust_dns_resolver::proto::iocompat::AsyncIoTokioAsStd;
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TcpStream>>::new(addr);
        let (client, bg) = AsyncClient::new(Box::new(stream), sender, None).await?;
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
