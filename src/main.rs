use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use failure::format_err;
use futures::{
    future::{self, Either},
    Future,
};
use structopt::StructOpt;
use tokio::runtime::current_thread::Runtime;
use trust_dns::rr;

use tdns_update::{
    record::{RecordSet, RsData},
    tsig,
    update::{monitor_update, perform_update, Expectation, Monitor, Operation, Update},
    util, DnsOpen, RuntimeHandle, TcpOpen, UdpOpen,
};

/// Wait for a DNS entry to obtain a specified state.
#[derive(StructOpt)]
struct Opt {
    /// Specify the recusor to use, including the port number.
    ///
    /// If not specified, the first nameserver specified in `/etc/resolv.conf`
    /// is used.
    #[structopt(long)]
    resolver: Option<SocketAddr>,
    /// Timeout in seconds for how long to wait in total for a successful
    /// update.
    #[structopt(long)]
    timeout: Option<u64>,
    #[structopt(long)]
    zone: Option<rr::Name>,
    /// Entry to monitor.
    entry: rr::Name,
    /// Expected query response.
    rs_data: RsData,
    /// TSIG key in NAME:ALGORITHM:BASE64-DATA notation.
    #[structopt(long)]
    key: Option<String>,
    /// Excluded IP address.
    #[structopt(long)]
    exclude: Option<IpAddr>,
    /// Do not perform the update.
    #[structopt(long)]
    no_op: bool,
    /// Delete matching records.
    #[structopt(long)]
    delete: bool,
    /// Create the specified records.
    ///
    /// Ensures that no records for the added types exist.
    #[structopt(long)]
    create: bool,
    /// Do not monitor nameservers for the update.
    #[structopt(long)]
    no_wait: bool,
    /// Show informational messages during execution.
    #[structopt(long, short)]
    verbose: bool,
    /// The number of seconds to wait between checking.
    #[structopt(long)]
    interval: Option<u64>,
    /// Use TCP for all DNS requests.
    #[structopt(long)]
    tcp: bool,
}

impl Opt {
    fn get_resolver_addr(&self) -> Result<SocketAddr, failure::Error> {
        self.resolver
            .or_else(util::get_system_resolver)
            .ok_or_else(|| format_err!("could not obtain resolver address from operating system"))
    }
    fn to_update(&self) -> Result<Option<Update>, failure::Error> {
        let zone = self.zone.clone().unwrap_or_else(|| self.entry.base_name());
        if self.no_op {
            return Ok(None);
        }
        let operation = match (self.create, self.delete) {
            (true, true) => return Err(format_err!("Conflicting operations specified")),
            (true, false) => {
                Operation::Create(RecordSet::new(self.entry.clone(), self.rs_data.clone()))
            }
            (false, true) => {
                Operation::Delete(RecordSet::new(self.entry.clone(), self.rs_data.clone()))
            }
            (false, false) => return Ok(None),
        };
        let tsig_key = self
            .key
            .clone()
            .map(|s| {
                let parts: Vec<_> = s.split(':').collect();
                if parts.len() != 3 {
                    return Err(format_err!(
                        "expected three colon-separated parts, found {}",
                        parts.len()
                    ));
                }
                let (name, algo, data) = (parts[0], parts[1], parts[2]);
                Ok((
                    name.parse()?,
                    tsig::Algorithm::from_name(&algo.parse()?)?,
                    base64::decode(data)?,
                ))
            })
            .transpose()?;
        Ok(Some(Update {
            operation,
            zone,
            tsig_key,
        }))
    }

    fn to_monitor(&self) -> Result<Option<Monitor>, failure::Error> {
        let zone = self.zone.clone().unwrap_or_else(|| self.entry.base_name());
        if self.no_wait {
            return Ok(None);
        }
        Ok(Some(Monitor {
            zone,
            entry: self.entry.clone(),
            expectation: if self.delete {
                Expectation::Empty(self.rs_data.record_type())
            } else {
                Expectation::Is(RecordSet::new(self.entry.clone(), self.rs_data.clone()))
            },
            exclude: self.exclude.into_iter().collect(),
            interval: Duration::from_secs(self.interval.unwrap_or(1)),
            timeout: Duration::from_secs(self.timeout.unwrap_or(60)),
            verbose: self.verbose,
        }))
    }
}

fn run_with_dns<D: DnsOpen + 'static>(
    runtime: RuntimeHandle,
    mut dns: D,
    opt: Opt,
) -> Result<Box<dyn Future<Item = (), Error = failure::Error>>, failure::Error> {
    let resolver = dns.open(runtime.clone(), opt.get_resolver_addr()?);
    let maybe_update = match opt.to_update()? {
        Some(update) => Either::A(perform_update(
            runtime.clone(),
            dns.clone(),
            resolver.clone(),
            update,
        )?),
        None => Either::B(future::ok(())),
    };
    let maybe_monitor = match opt.to_monitor()? {
        Some(monitor) => Either::A(monitor_update(runtime, dns, resolver, monitor)),
        None => Either::B(future::ok(())),
    };
    Ok(Box::new(maybe_update.and_then(|_| maybe_monitor)))
}

fn run(opt: Opt) -> Result<(), failure::Error> {
    let mut runtime = Runtime::new().unwrap();
    let app = if opt.tcp {
        run_with_dns(runtime.handle(), TcpOpen, opt)?
    } else {
        run_with_dns(runtime.handle(), UdpOpen, opt)?
    };
    runtime.block_on(app).map(|_| ())
}

fn main() {
    let opt = Opt::from_args();
    let rc = match run(opt) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("error: {}", e);
            1
        }
    };
    std::process::exit(rc);
}
