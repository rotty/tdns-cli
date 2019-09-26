/// An abstraction over different ways to do DNS queries.
use std::net::SocketAddr;

use tokio_tcp::TcpStream;
use tokio_udp::UdpSocket;
use trust_dns::{
    client::{BasicClientHandle, ClientFuture, ClientHandle},
    proto::{udp::UdpResponse, xfer::dns_multiplexer::DnsMultiplexerSerialResponse},
    tcp::TcpClientStream,
    udp::UdpClientStream,
};

pub type RuntimeHandle = tokio::runtime::current_thread::Handle;

pub trait DnsOpen {
    type Client: ClientHandle;
    fn open(runtime: RuntimeHandle, addr: SocketAddr) -> Self::Client;
}

pub struct TcpOpen;

impl DnsOpen for TcpOpen {
    type Client = BasicClientHandle<DnsMultiplexerSerialResponse>;
    fn open(runtime: RuntimeHandle, addr: SocketAddr) -> Self::Client {
        let (connect, handle) = TcpClientStream::<TcpStream>::new(addr);
        let (bg, client) = ClientFuture::new(connect, handle, None);
        runtime.spawn(bg).unwrap();
        client
    }
}

pub struct UdpOpen;

impl DnsOpen for UdpOpen {
    type Client = BasicClientHandle<UdpResponse<tokio_udp::UdpSocket>>;
    fn open(runtime: RuntimeHandle, addr: SocketAddr) -> Self::Client {
        let stream = UdpClientStream::<UdpSocket>::new(addr);
        let (bg, client) = ClientFuture::connect(stream);
        runtime.spawn(bg).unwrap();
        client
    }
}
