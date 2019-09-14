use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use failure::format_err;
use futures::{
    future::{self, Either},
    Future,
};
use structopt::StructOpt;
use tokio::{prelude::*, runtime::current_thread::Runtime, timer::Delay};
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

#[derive(StructOpt)]
struct Opt {
    #[structopt(long = "recursor")]
    recursor: SocketAddr,
    #[structopt(long = "timeout")]
    timeout: Option<u64>,
    domain: rr::Name,
    entry: rr::Name,
    text: String,
}

fn main() {
    let opt = Opt::from_args();
    let mut runtime = Runtime::new().unwrap();
    let recursor = open_recursor(runtime.handle(), opt.recursor);
    let name = opt.domain;
    let handle = runtime.handle();
    let entry = opt.entry;
    let timeout = opt.timeout.unwrap_or(5);

    let get_authorative = get_ns_records(recursor.clone(), name).map_err(failure::Error::from);
    let expected = vec![rr::RData::TXT(rr::rdata::txt::TXT::new(vec![opt.text]))];
    let client = get_authorative
        .and_then(move |authorative| {
            future::join_all(authorative.into_iter().map(move |record| {
                let expected = expected.clone();
                poll_entry(
                    handle.clone(),
                    recursor.clone(),
                    record.rdata().as_ns().unwrap().clone(),
                    entry.clone(),
                    RecordType::A,
                    move |server, records| {
                        let rdata = records.iter().map(Record::rdata);
                        println!("got records from {:?} {:?}", server, records);
                        rdata.eq(expected.iter())
                    },
                )
            }))
        })
        .timeout(Duration::from_secs(timeout))
        .map_err(|e| {
            e.into_inner().unwrap_or_else(|| {
                format_err!("timeout; update not complete within {} seconds", timeout)
            })
        });
    let rc = match runtime.block_on(client) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("error: {}", e);
            1
        }
    };
    std::process::exit(rc);
}
