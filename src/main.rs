use std::{
    collections::BTreeSet,
    convert::TryFrom,
    fmt,
    iter::FromIterator,
    net::{self, IpAddr, SocketAddr},
    net::{Ipv4Addr, Ipv6Addr},
    rc::Rc,
    str::FromStr,
    string::FromUtf8Error,
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
    proto::{
        op::{message::Message, query::Query},
        xfer::{dns_handle::DnsHandle, dns_request::DnsRequest},
    },
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

fn connect_authorative(runtime: RuntimeHandle, addr: IpAddr) -> impl DnsHandle {
    let stream = UdpClientStream::<UdpSocket>::new(SocketAddr::new(addr, 53));
    let (bg, client) = ClientFuture::connect(stream);
    runtime.spawn(bg).unwrap();
    client
}

fn resolve_authorative(
    recursor: impl DnsHandle,
    server_name: rr::Name,
) -> impl Future<Item = IpAddr, Error = failure::Error> {
    let server_name_err = server_name.clone();
    query_ip_addr(recursor, &server_name)
        .map_err(failure::Error::from)
        .and_then(move |addrs| {
            let client = addrs
                .first()
                .cloned()
                .ok_or_else(|| format_err!("could not resolve server name: {}", server_name_err))?;
            Ok(client)
        })
}

fn poll_entries<F>(
    mut server: impl DnsHandle,
    server_name: rr::Name,
    name: rr::Name,
    record_types: &[RecordType],
    interval: Duration,
    done: F,
) -> impl Future<Item = (), Error = failure::Error>
where
    F: Fn(&rr::Name, &[Record]) -> bool + 'static,
{
    let mut message = Message::new();
    message.add_queries(
        record_types
            .iter()
            .map(|rtype| Query::query(name.clone(), *rtype)),
    );
    use future::Loop;
    let poller = future::loop_fn(done, move |done| {
        let server_name = server_name.clone();
        server
            .send(DnsRequest::new(message.clone(), Default::default()))
            .map_err(failure::Error::from)
            .and_then(move |response: DnsResponse| {
                if done(&server_name, response.answers()) {
                    Either::A(future::ok(Loop::Break(())))
                } else {
                    let when = Instant::now() + interval;
                    Either::B(
                        Delay::new(when)
                            .map_err(failure::Error::from)
                            .map(|_| Loop::Continue(done)),
                    )
                }
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
    expected: Vec<Data>,
    #[structopt(long = "exclude")]
    exclude: Option<IpAddr>,
    #[structopt(long = "verbose", short = "v")]
    verbose: bool,
    #[structopt(long = "interval")]
    interval: Option<u64>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct RecordSet(BTreeSet<Data>);

impl RecordSet {
    fn to_record_types(&self) -> Vec<RecordType> {
        self.0.iter().map(Data::to_record_type).collect()
    }

    fn satisfied_by(&self, rrs: &[rr::Record]) -> bool {
        rrs.iter()
            .map(|rr| Data::try_from(rr.rdata()))
            .collect::<Result<Vec<_>, _>>()
            .ok()
            .map(|items| self == &RecordSet::from_iter(items))
            .unwrap_or(false)
    }
}

impl fmt::Display for RecordSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[")?;
        for (i, item) in self.0.iter().enumerate() {
            if i + 1 < self.0.len() {
                write!(f, "{}, ", item)?;
            } else {
                write!(f, "{}", item)?;
            }
        }
        write!(f, "]")?;
        Ok(())
    }
}

impl FromIterator<Data> for RecordSet {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = Data>,
    {
        RecordSet(iter.into_iter().collect())
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
enum Data {
    // Simplified representation, containing only a single part.
    TXT(String),
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
}

impl Data {
    fn to_record_type(&self) -> RecordType {
        match self {
            Data::TXT(_) => RecordType::TXT,
            Data::A(_) => RecordType::A,
            Data::AAAA(_) => RecordType::AAAA,
        }
    }
}

impl TryFrom<&rr::RData> for Data {
    type Error = TryFromRDataError;

    fn try_from(rdata: &rr::RData) -> Result<Self, Self::Error> {
        match rdata {
            rr::RData::A(addr) => Ok(Data::A(addr.clone())),
            rr::RData::AAAA(addr) => Ok(Data::AAAA(addr.clone())),
            rr::RData::TXT(txt) => Ok(Data::TXT(
                txt.txt_data()
                    .iter()
                    .map(|item| {
                        String::from_utf8(item.to_vec()).map_err(TryFromRDataError::FromUtf8)
                    })
                    .collect::<Result<_, _>>()?,
            )),
            _ => Err(TryFromRDataError::UnsupportedType(rdata.to_record_type())),
        }
    }
}

enum TryFromRDataError {
    UnsupportedType(RecordType),
    FromUtf8(FromUtf8Error),
}

impl fmt::Display for Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Data::TXT(content) => {
                if content.chars().any(char::is_whitespace) {
                    write!(f, "TXT:'{}'", content)
                } else {
                    write!(f, "TXT:{}", content)
                }
            }
            Data::A(addr) => write!(f, "A:{}", addr),
            Data::AAAA(addr) => write!(f, "AAAA:{}", addr),
        }
    }
}

impl FromStr for Data {
    type Err = DataParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(DataParseError::MissingType);
        }
        let (rtype, rdata) = (parts[0].to_uppercase(), parts[1]);
        match rtype.as_str() {
            "TXT" => Ok(Data::TXT(rdata.into())),
            "A" => Ok(Data::A(rdata.parse().map_err(DataParseError::Addr)?)),
            "AAAA" => Ok(Data::AAAA(rdata.parse().map_err(DataParseError::Addr)?)),
            _ => Err(DataParseError::UnknownType),
        }
    }
}

#[derive(Debug)]
enum DataParseError {
    MissingType,
    UnknownType,
    Addr(net::AddrParseError),
}

impl fmt::Display for DataParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DataParseError::*;
        match self {
            MissingType => write!(f, "missing type"),
            UnknownType => write!(f, "unknown type"),
            Addr(e) => write!(f, "invalid address: {}", e),
        }
    }
}

struct ShowRecordData<'a>(&'a [Record]);

impl<'a> fmt::Display for ShowRecordData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[")?;
        for (i, item) in self.0.iter().enumerate() {
            match Data::try_from(item.rdata()) {
                Ok(data) => write!(f, "{}", data)?,
                Err(e) => match e {
                    TryFromRDataError::UnsupportedType(rtype) => write!(f, "unknown:{}", rtype)?,
                    TryFromRDataError::FromUtf8(e) => {
                        write!(f, "non-utf8:'{}'", String::from_utf8_lossy(e.as_bytes()))?
                    }
                },
            }
            if i + 1 < self.0.len() {
                write!(f, ", ")?;
            }
        }
        write!(f, "]")?;
        Ok(())
    }
}

fn poll_server(
    server: impl DnsHandle,
    server_name: rr::Name,
    entry: rr::Name,
    expected: Rc<RecordSet>,
    interval: Duration,
    verbose: bool,
) -> impl Future<Item = (), Error = failure::Error> {
    poll_entries(
        server,
        server_name,
        entry,
        expected.to_record_types().as_slice(),
        interval,
        move |server, records| {
            let matched = expected.satisfied_by(records);
            if verbose {
                if !matched {
                    println!(
                        "{}: records not matching: expected {}, found {}",
                        server,
                        expected,
                        ShowRecordData(records),
                    );
                } else {
                    println!("{}: match found", server);
                }
            }
            matched
        },
    )
}

fn main() {
    let opt = Opt::from_args();
    let mut runtime = Runtime::new().unwrap();
    let recursor = open_recursor(runtime.handle(), opt.recursor);
    let name = opt.domain;
    let handle = runtime.handle();
    let entry = opt.entry.append_name(&name);
    let timeout = opt.timeout.unwrap_or(5);
    let exclude = opt.exclude;
    let interval = opt.interval;

    let get_authorative = get_ns_records(recursor.clone(), name).map_err(failure::Error::from);
    let expected = Rc::new(RecordSet::from_iter(opt.expected));
    let verbose = opt.verbose;
    let client = get_authorative
        .and_then(move |authorative| {
            future::join_all(
                authorative
                    .into_iter()
                    .filter_map(|r| r.rdata().as_ns().cloned())
                    .map(move |server_name| {
                        let handle = handle.clone();
                        let server_name = server_name.clone();
                        let resolve = resolve_authorative(recursor.clone(), server_name.clone())
                            .map(move |addr| {
                                if Some(addr) == exclude {
                                    None
                                } else {
                                    Some(connect_authorative(handle.clone(), addr))
                                }
                            });
                        let server_name = server_name.clone();
                        let entry = entry.clone();
                        let expected = Rc::clone(&expected);
                        resolve.and_then(move |maybe_server| match maybe_server {
                            None => Either::A(future::ok(())),
                            Some(server) => Either::B(poll_server(
                                server.clone(),
                                server_name,
                                entry,
                                expected,
                                Duration::from_secs(interval.unwrap_or(1)),
                                verbose,
                            )),
                        })
                    }),
            )
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
