use std::{
    net::{IpAddr, SocketAddr},
    rc::Rc,
    time::{Duration, Instant},
};

use futures::{
    future::{self, Either},
    Future,
};
use tokio::timer::Delay;
use trust_dns::{
    client::ClientHandle,
    op::DnsResponse,
    proto::{
        op::{message::Message, query::Query},
        xfer::dns_request::DnsRequest,
    },
    rr::{self, Record, RecordType},
};

use crate::{record::RecordSet, util::ShowRecordData};

#[derive(Debug)]
pub struct Settings {
    pub resolver: SocketAddr,
    pub expected: RecordSet,
    pub domain: rr::Name,
    pub entry: rr::Name,
    pub interval: Duration,
    pub timeout: Duration,
    pub verbose: bool,
    pub exclude: Vec<IpAddr>,
}

pub fn poll_entries<F>(
    mut server: impl ClientHandle,
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
    future::loop_fn(done, move |done| {
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
    })
}

pub fn poll_server(
    server: impl ClientHandle,
    server_name: rr::Name,
    settings: Rc<Settings>,
) -> impl Future<Item = (), Error = failure::Error> {
    poll_entries(
        server,
        server_name,
        settings.entry.clone(),
        settings.expected.to_record_types().as_slice(),
        settings.interval,
        move |server, records| {
            let matched = settings.expected.satisfied_by(records);
            if settings.verbose {
                if !matched {
                    println!(
                        "{}: records not matching: expected {}, found {}",
                        server,
                        settings.expected,
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
