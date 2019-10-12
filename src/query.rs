use futures::{future, Future};

use trust_dns::{
    client::ClientHandle,
    proto::xfer::{DnsHandle, DnsResponse},
    rr,
};

#[derive(Debug, Clone)]
pub struct Query {
    pub entry: rr::Name,
    pub record_types: Vec<rr::RecordType>,
}

pub fn perform_query(
    mut resolver: impl DnsHandle,
    options: Query,
) -> impl Future<Item = Vec<DnsResponse>, Error = failure::Error> {
    let entry = options.entry;
    future::join_all(options.record_types.into_iter().map(move |rtype| {
        resolver
            .query(entry.clone(), rr::DNSClass::IN, rtype)
            .map_err(Into::into)
    }))
}

pub fn print_dns_response(responses: &[DnsResponse], _options: &Query) {
    for response in responses {
        for answer in response.answers() {
            use rr::RData::*;
            match answer.rdata() {
                A(addr) => println!("{}", addr),
                AAAA(addr) => println!("{}", addr),
                TXT(txt) => {
                    for (i, data) in txt.txt_data().iter().enumerate() {
                        // TODO: proper (lossless) display of TXT data
                        let content = String::from_utf8_lossy(data);
                        if i + 1 < txt.txt_data().len() {
                            print!(r#""{}" "#, content);
                        } else {
                            println!(r#""{}""#, content);
                        }
                    }
                }
                NS(name) => {
                    println!("{}", name);
                }
                MX(mx) => {
                    println!("{} {}", mx.preference(), mx.exchange());
                }
                SOA(soa) => {
                    println!(
                        "{} {} {} {} {} {} {}",
                        soa.mname(),
                        soa.rname(),
                        soa.serial(),
                        soa.refresh(),
                        soa.retry(),
                        soa.expire(),
                        soa.minimum()
                    );
                }
                // TODO: display other records properly
                other => println!("{:?}", other),
            }
        }
    }
}
