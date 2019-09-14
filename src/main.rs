use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use failure::format_err;
use futures::{
    future::{self, Either},
    Future,
};
use tokio::{runtime::current_thread::Runtime, timer::Delay};
use tokio_udp::UdpSocket;
use trust_dns::{
    client::{ClientFuture, ClientHandle},
    op::DnsResponse,
    proto::xfer::dns_handle::DnsHandle,
    rr::{self, DNSClass, Record, RecordType},
    udp::UdpClientStream,
};

type DnsError = trust_dns::error::ClientError;
type RuntimeHandle = tokio::runtime::current_thread::Handle;

fn open_recursor(runtime: RuntimeHandle, address: SocketAddr) -> impl DnsHandle {
    let stream = UdpClientStream::<UdpSocket>::new(address);
    let (bg, client) = ClientFuture::connect(stream);
    runtime.spawn(bg).unwrap();
    client
}

fn query_ip_addr(
    mut recursor: impl DnsHandle,
    name: &rr::Name,
) -> impl Future<Item = Vec<IpAddr>, Error = DnsError> {
    // FIXME: IPv6
    recursor
        .query(name.clone(), DNSClass::IN, RecordType::A)
        .map(|response| {
            response
                .answers()
                .iter()
                .filter_map(|r| r.rdata().to_ip_addr())
                .collect()
        })
}

fn get_ns_records<R>(
    mut recursor: R,
    domain: rr::Name,
) -> impl Future<Item = Vec<Record>, Error = DnsError>
where
    R: DnsHandle,
{
    let query = recursor
        .query(domain, DNSClass::IN, RecordType::NS)
        .map(|response| response.answers().to_vec());
    query
}

fn poll_entry<F>(
    runtime: RuntimeHandle,
    recursor: impl DnsHandle,
    server_name: rr::Name,
    name: rr::Name,
    record_type: RecordType,
    done: F,
) -> impl Future<Item = (), Error = failure::Error>
where
    F: Fn(&rr::Name, &[Record]) -> bool + 'static,
{
    let server_name_err = server_name.clone();
    let resolve = query_ip_addr(recursor, &server_name)
        .map_err(failure::Error::from)
        .and_then(move |addrs| {
            let client = addrs
                .first()
                .map(|addr| {
                    let stream = UdpClientStream::<UdpSocket>::new(SocketAddr::new(*addr, 53));
                    let (bg, client) = ClientFuture::connect(stream);
                    runtime.spawn(bg).unwrap();
                    client
                })
                .ok_or_else(|| format_err!("could not resolve server name: {}", server_name_err))?;
            Ok(client)
        });

    use future::Loop;
    let poller = resolve.and_then(move |mut client| {
        future::loop_fn(done, move |done| {
            let server_name = server_name.clone();
            client
                .query(name.clone(), DNSClass::IN, record_type)
                .map_err(failure::Error::from)
                .and_then(move |response: DnsResponse| {
                    if done(&server_name, response.answers()) {
                        Either::A(future::ok(Loop::Break(())))
                    } else {
                        let when = Instant::now() + Duration::from_millis(500);
                        Either::B(
                            Delay::new(when)
                                .map_err(failure::Error::from)
                                .map(|_| Loop::Continue(done)),
                        )
                    }
                })
        })
    });
    poller
}

fn main() {
    let address = "8.8.8.8:53".parse().unwrap();
    let mut runtime = Runtime::new().unwrap();
    let recursor = open_recursor(runtime.handle(), address);
    let name = "r0tty.org.".parse().unwrap();
    let handle = runtime.handle();

    let get_authorative = get_ns_records(recursor.clone(), name).map_err(failure::Error::from);
    let client = get_authorative
        .and_then(move |authorative| {
            future::join_all(authorative.into_iter().map(move |record| {
                poll_entry(
                    handle.clone(),
                    recursor.clone(),
                    record.rdata().as_ns().unwrap().clone(),
                    "ns1.r0tty.org.".parse().unwrap(),
                    RecordType::A,
                    |server, records| {
                        let rdata: Vec<_> = records.iter().map(Record::rdata).collect();
                        println!("got records from {:?} {:?}", server, records);
                        if rdata.as_slice()
                            == &[&rr::RData::TXT(rr::rdata::txt::TXT::new(vec![
                                "foobar".into()
                            ]))]
                        {
                            true
                        } else {
                            false
                        }
                    },
                )
            }))
        })
        .map_err(|e| eprintln!("error: {}", e));
    runtime.block_on(client).unwrap();
}
