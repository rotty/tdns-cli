use std::{
    convert::TryFrom,
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
    rr::{self, Record},
};

use crate::record::RecordSet;

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

fn poll_entries<F>(
    mut server: impl ClientHandle,
    server_name: rr::Name,
    settings: Rc<Settings>,
    report: F,
) -> impl Future<Item = (), Error = failure::Error>
where
    F: Fn(&rr::Name, &[Record], bool) + 'static,
{
    use future::Loop;
    future::loop_fn(report, move |report| {
        let server_name = server_name.clone();
        let settings = Rc::clone(&settings);
        server
            .query(
                settings.entry.clone(),
                settings.expected.dns_class(),
                settings.expected.record_type(),
            )
            .map_err(failure::Error::from)
            .and_then(move |response: DnsResponse| {
                let answers = response.answers();
                let hit = settings.expected.satisfied_by(answers);
                report(&server_name, answers, hit);
                if hit {
                    Either::A(future::ok(Loop::Break(())))
                } else {
                    let when = Instant::now() + settings.interval;
                    Either::B(
                        Delay::new(when)
                            .map_err(failure::Error::from)
                            .map(|_| Loop::Continue(report)),
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
        Rc::clone(&settings),
        move |server, records, hit| {
            if settings.verbose {
                if hit {
                    println!("{}: match found", server);
                } else {
                    let rset = match RecordSet::try_from(records) {
                        Ok(rs) => format!("{}", rs.data()),
                        Err(e) => format!("{}", e),
                    };
                    println!(
                        "{}: records not matching: expected {}, found {}",
                        server,
                        settings.expected.data(),
                        rset,
                    );
                }
            }
        },
    )
}
