/// An abstraction over different ways to do DNS queries.
use std::net::SocketAddr;

use futures::Future;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use trust_dns::{
    client::{BasicClientHandle, ClientFuture, ClientHandle},
    proto::{udp::UdpResponse, xfer::dns_multiplexer::DnsMultiplexerSerialResponse},
    rr,
    tcp::TcpClientStream,
    udp::UdpClientStream,
};
use trust_dns_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    error::ResolveError,
    lookup, lookup_ip, AsyncResolver, BackgroundLookup, BackgroundLookupIp,
};

pub type RuntimeHandle = tokio::runtime::current_thread::Handle;

pub trait Resolver: Clone {
    type Lookup: Future<Output = Result<lookup::Lookup, ResolveError>>;
    type LookupIp: Future<Output = Result<lookup_ip::LookupIp, ResolveError>>;
    type LookupSoa: Future<Output = Result<lookup::SoaLookup, ResolveError>>;
    type LookupNs: Future<Output = Result<lookup::NsLookup, ResolveError>>;
    fn lookup(&self, name: rr::Name, rtype: rr::RecordType) -> Self::Lookup;
    fn lookup_ip(&self, host: rr::Name) -> Self::LookupIp;
    fn lookup_soa(&self, name: rr::Name) -> Self::LookupSoa;
    fn lookup_ns(&self, name: rr::Name) -> Self::LookupNs;
}

impl Resolver for AsyncResolver {
    type Lookup = BackgroundLookup;
    type LookupIp = BackgroundLookupIp;
    type LookupSoa = BackgroundLookup<lookup::SoaLookupFuture>;
    type LookupNs = BackgroundLookup<lookup::NsLookupFuture>;

    fn lookup(&self, name: rr::Name, rtype: rr::RecordType) -> Self::Lookup {
        AsyncResolver::lookup(self, name, rtype)
    }

    fn lookup_ip(&self, host: rr::Name) -> Self::LookupIp {
        AsyncResolver::lookup_ip(self, host)
    }

    fn lookup_soa(&self, name: rr::Name) -> Self::LookupSoa {
        AsyncResolver::soa_lookup(self, name)
    }

    fn lookup_ns(&self, name: rr::Name) -> Self::LookupNs {
        AsyncResolver::ns_lookup(self, name)
    }
}

pub trait Backend: Clone {
    type Client: ClientHandle;
    type Resolver: Resolver;
    fn open(&mut self, runtime: RuntimeHandle, addr: SocketAddr) -> Self::Client;
    fn open_resolver(&mut self, runtime: RuntimeHandle, addr: SocketAddr) -> Self::Resolver;
    fn open_system_resolver(
        &mut self,
        runtime: RuntimeHandle,
    ) -> Result<Self::Resolver, ResolveError>;
}

#[derive(Debug, Clone)]
pub struct TcpBackend;

impl Backend for TcpBackend {
    type Client = BasicClientHandle<DnsMultiplexerSerialResponse>;
    type Resolver = AsyncResolver;

    fn open(&mut self, runtime: RuntimeHandle, addr: SocketAddr) -> Self::Client {
        let (connect, handle) = TcpClientStream::<TcpStream>::new(addr);
        let (bg, client) = ClientFuture::new(connect, handle, None);
        runtime.spawn(bg).unwrap();
        client
    }

    fn open_resolver(&mut self, runtime: RuntimeHandle, addr: SocketAddr) -> Self::Resolver {
        make_resolver(runtime, addr, Protocol::Tcp)
    }

    fn open_system_resolver(
        &mut self,
        runtime: RuntimeHandle,
    ) -> Result<Self::Resolver, ResolveError> {
        let (resolver, bg) = AsyncResolver::from_system_conf()?;
        runtime.spawn(bg).unwrap();
        Ok(resolver)
    }
}

#[derive(Debug, Clone)]
pub struct UdpBackend;

impl Backend for UdpBackend {
    type Client = BasicClientHandle<UdpResponse>;
    type Resolver = AsyncResolver;

    fn open(&mut self, runtime: RuntimeHandle, addr: SocketAddr) -> Self::Client {
        let stream = UdpClientStream::<UdpSocket>::new(addr);
        let (bg, client) = ClientFuture::connect(stream);
        runtime.spawn(bg).unwrap();
        client
    }
    fn open_resolver(&mut self, runtime: RuntimeHandle, addr: SocketAddr) -> Self::Resolver {
        make_resolver(runtime, addr, Protocol::Udp)
    }

    fn open_system_resolver(
        &mut self,
        runtime: RuntimeHandle,
    ) -> Result<Self::Resolver, ResolveError> {
        let (resolver, bg) = AsyncResolver::from_system_conf()?;
        runtime.spawn(bg).unwrap();
        Ok(resolver)
    }
}

fn make_resolver(runtime: RuntimeHandle, addr: SocketAddr, protocol: Protocol) -> AsyncResolver {
    let mut config = ResolverConfig::new();
    config.add_name_server(NameServerConfig {
        socket_addr: addr,
        protocol,
        tls_dns_name: None,
    });
    let (resolver, bg) = AsyncResolver::new(config, ResolverOpts::default());
    runtime.spawn(bg).unwrap();
    resolver
}
