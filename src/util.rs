use std::{
    fs,
    net::{IpAddr, SocketAddr},
};

use failure::format_err;
use futures::{future, Future};
use trust_dns::{
    client::ClientHandle,
    op::DnsResponse,
    proto::op::query::Query,
    rr::{self, Record, RecordType},
};

pub fn get_system_resolver() -> Option<SocketAddr> {
    use resolv_conf::{Config, ScopedIp};
    let resolv_conf = fs::read("/etc/resolv.conf").ok()?;
    let config = Config::parse(&resolv_conf).ok()?;
    config.nameservers.iter().find_map(|scoped| match scoped {
        ScopedIp::V4(v4) => Some(SocketAddr::new(v4.clone().into(), 53)),
        ScopedIp::V6(_, _) => None, // TODO: IPv6 support
    })
}

pub fn dns_query(
    mut recursor: impl ClientHandle,
    query: Query,
) -> impl Future<Item = DnsResponse, Error = failure::Error> {
    use future::Loop;
    const MAX_TRIES: usize = 3;
    future::loop_fn(0, move |count| {
        let run_query = recursor.lookup(query.clone(), Default::default());
        let name = query.name().clone();
        run_query.then(move |result| match result {
            Ok(addrs) => future::ok(Loop::Break(addrs)),
            Err(_) if count < MAX_TRIES => future::ok(Loop::Continue(count + 1)),
            Err(e) => future::err(format_err!(
                "could not resolve server name '{}' (max retries reached): {}",
                name,
                e
            )),
        })
    })
}

pub fn query_ip_addr(
    recursor: impl ClientHandle,
    name: rr::Name,
) -> impl Future<Item = Vec<IpAddr>, Error = failure::Error> + 'static {
    // FIXME: IPv6
    dns_query(recursor, Query::query(name, RecordType::A)).map(|response| {
        response
            .answers()
            .iter()
            .filter_map(|r| r.rdata().to_ip_addr())
            .collect()
    })
}

pub fn get_ns_records<R>(
    recursor: R,
    domain: rr::Name,
) -> impl Future<Item = Vec<Record>, Error = failure::Error>
where
    R: ClientHandle,
{
    dns_query(recursor, Query::query(domain, RecordType::NS))
        .map(|response| response.answers().to_vec())
}

pub fn resolve_authorative(
    recursor: impl ClientHandle,
    server_name: rr::Name,
) -> impl Future<Item = IpAddr, Error = failure::Error> {
    query_ip_addr(recursor.clone(), server_name.clone()).and_then(move |addrs| {
        // TODO: handle multiple addresses
        if let Some(addr) = addrs.first().cloned() {
            Ok(addr)
        } else {
            Err(format_err!(
                "could not resolve server '{}': no addresses found",
                server_name
            ))
        }
    })
}
