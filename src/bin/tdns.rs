use std::{
    fs,
    io::{BufRead, BufReader},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
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

use tdns_cli::{
    query::{perform_query, print_dns_response, Query},
    record::{RecordSet, RsData},
    tsig,
    update::{monitor_update, perform_update, Expectation, Monitor, Operation, Update},
    util::{self, CommaSeparated},
    DnsOpen, RuntimeHandle, TcpOpen, UdpOpen,
};

/// DNS client utilities
#[derive(StructOpt)]
enum Tdns {
    /// Update a DNS entry
    Update(UpdateOpt),
    /// Issue DNS queries
    Query(QueryOpt),
}

#[derive(StructOpt)]
struct CommonOpt {
    /// Specify the recusor to use, including the port number.
    ///
    /// If not specified, the first nameserver specified in `/etc/resolv.conf`
    /// is used.
    #[structopt(long)]
    resolver: Option<SocketAddr>,
    /// Use TCP for all DNS requests.
    #[structopt(long)]
    tcp: bool,
}

impl CommonOpt {
    fn get_resolver_addr(&self) -> Result<SocketAddr, failure::Error> {
        self.resolver
            .or_else(util::get_system_resolver)
            .ok_or_else(|| format_err!("could not obtain resolver address from operating system"))
    }
}

#[derive(StructOpt)]
struct QueryOpt {
    #[structopt(flatten)]
    common: CommonOpt,
    entry: rr::Name,
    #[structopt(long = "type", short = "t")]
    record_types: Option<CommaSeparated<rr::RecordType>>,
}

impl QueryOpt {
    fn to_query(&self) -> Result<Query, failure::Error> {
        Ok(Query {
            entry: self.entry.clone(),
            record_types: self
                .record_types
                .as_ref()
                .map(|cs| cs.to_vec())
                .unwrap_or_else(|| vec![rr::RecordType::A]),
        })
    }
}

#[derive(StructOpt)]
struct UpdateOpt {
    #[structopt(flatten)]
    common: CommonOpt,
    /// Timeout in seconds for how long to wait in total for a successful
    /// update.
    #[structopt(long)]
    timeout: Option<u64>,
    #[structopt(long)]
    server: Option<util::SocketName>,
    #[structopt(long)]
    zone: Option<rr::Name>,
    /// Entry to update and/or monitor.
    entry: rr::Name,
    /// RRset for update and/or monitoring.
    rs_data: Option<RsData>,
    /// TSIG key in NAME:ALGORITHM:BASE64-DATA notation, or just NAME when used
    /// in combination with --key-file.
    #[structopt(long)]
    key: Option<String>,
    #[structopt(long)]
    key_file: Option<PathBuf>,
    /// Excluded IP address.
    #[structopt(long)]
    exclude: Option<IpAddr>,
    /// The TTL for added records.
    #[structopt(long)]
    ttl: Option<u32>,
    /// Do not perform the update.
    #[structopt(long)]
    no_op: bool,
    /// Delete matching records.
    #[structopt(long)]
    delete: bool,
    /// Append records to the zone.
    #[structopt(long)]
    append: bool,
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
}

impl UpdateOpt {
    fn get_rset(&self) -> Result<RecordSet, failure::Error> {
        let rs_data = self
            .rs_data
            .clone()
            .ok_or_else(|| format_err!("Missing RS-DATA argument"))?;
        Ok(RecordSet::new(self.entry.clone(), rs_data))
    }

    fn get_operation(&self) -> Result<Option<Operation>, failure::Error> {
        let op_flags = &[self.create, self.delete, self.append];
        let operation = match op_flags.iter().filter(|&&flag| flag).count() {
            0 => return Ok(None),
            1 => match op_flags.iter().position(|flag| *flag).unwrap() {
                0 => Operation::Create(self.get_rset()?),
                1 => match &self.rs_data {
                    Some(rs_data) => {
                        Operation::Delete(RecordSet::new(self.entry.clone(), rs_data.clone()))
                    }
                    None => Operation::DeleteAll(self.entry.clone()),
                },
                2 => Operation::Append(self.get_rset()?),
                _ => unreachable!(),
            },
            _ => return Err(format_err!("Conflicting operations specified")),
        };
        Ok(Some(operation))
    }

    fn get_tsig_key(&self) -> Result<Option<tsig::Key>, failure::Error> {
        if let Some(key) = &self.key {
            let parts: Vec<_> = key.split(':').collect();
            match parts.len() {
                1 => {
                    let key_name = parts[0].parse()?;
                    if let Some(file_name) = &self.key_file {
                        Ok(Some(read_key(file_name, Some(&key_name))?))
                    } else {
                        Err(format_err!("--key-file option required with --key=NAME"))
                    }
                }
                3 => {
                    let (name, algo, data) = (parts[0], parts[1], parts[2]);
                    Ok(Some(tsig::Key::new(
                        name.parse()?,
                        tsig::Algorithm::from_name(&algo.parse()?)?,
                        base64::decode(data)?,
                    )))
                }
                _ => Err(format_err!(
                    "expected NAME or NAME:ALGORITHM:KEY, found {}",
                    key
                )),
            }
        } else if let Some(key_file) = &self.key_file {
            Ok(Some(read_key(key_file, None)?))
        } else {
            Ok(None)
        }
    }

    fn to_update(&self) -> Result<Option<Update>, failure::Error> {
        let zone = self.zone.clone().unwrap_or_else(|| self.entry.base_name());
        if self.no_op {
            return Ok(None);
        }
        Ok(Some(Update {
            operation: match self.get_operation()? {
                Some(operation) => operation,
                None => return Ok(None),
            },
            server: self.server.clone(),
            zone,
            tsig_key: self.get_tsig_key()?,
            ttl: self.ttl.unwrap_or(3600),
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
            expectation: match self.get_operation()? {
                None => Expectation::Is(self.get_rset()?),
                Some(Operation::Create(rset)) => Expectation::Is(rset),
                Some(Operation::Append(rset)) => Expectation::Contains(rset),
                Some(Operation::Delete(rset)) => {
                    if rset.is_empty() {
                        Expectation::Empty(rset.record_type())
                    } else {
                        Expectation::NotAny(rset)
                    }
                }
                Some(Operation::DeleteAll(_)) => Expectation::Empty(rr::RecordType::ANY),
            },
            exclude: self.exclude.into_iter().collect(),
            interval: Duration::from_secs(self.interval.unwrap_or(1)),
            timeout: Duration::from_secs(self.timeout.unwrap_or(60)),
            verbose: self.verbose,
        }))
    }
}

/// Reads a TSIG key from a file.
///
/// If `key_name` is `None`, the first key will be returned, otherwise the first
/// key matching `key_name` will be returned. When no matching key was found, or
/// the file could not be parsed, an error will be returned.
fn read_key(path: &Path, key_name: Option<&rr::Name>) -> Result<tsig::Key, failure::Error> {
    let file = fs::File::open(path)?;
    let input = BufReader::new(file);
    for line in input.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<_> = line.split(':').collect();
        if parts.len() != 3 {
            return Err(format_err!(
                "invalid line in key file; expected NAME:ALGORITHM:KEY, found {}",
                line
            ));
        }
        let name = parts[0].parse()?;
        if key_name.is_none() || Some(&name) == key_name {
            let (algo, data) = (parts[1], parts[2]);
            return Ok(tsig::Key::new(
                name,
                tsig::Algorithm::from_name(&algo.parse()?)?,
                base64::decode(data)?,
            ));
        }
    }
    if let Some(key_name) = key_name {
        Err(format_err!(
            "key {} not found in {}",
            key_name,
            path.display()
        ))
    } else {
        Err(format_err!("no key found in {}", path.display()))
    }
}

fn run_update<D: DnsOpen + 'static>(
    runtime: RuntimeHandle,
    mut dns: D,
    opt: UpdateOpt,
) -> Result<Box<dyn Future<Item = (), Error = failure::Error>>, failure::Error> {
    let resolver = dns.open(runtime.clone(), opt.common.get_resolver_addr()?);
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

fn run_query<D: DnsOpen + 'static>(
    runtime: RuntimeHandle,
    mut dns: D,
    opt: QueryOpt,
) -> Result<Box<dyn Future<Item = (), Error = failure::Error>>, failure::Error> {
    let resolver = dns.open(runtime.clone(), opt.common.get_resolver_addr()?);
    let query = opt.to_query()?;
    Ok(Box::new(
        perform_query(resolver, query.clone()).map(move |r| print_dns_response(&r, &query)),
    ))
}

fn run(tdns: Tdns) -> Result<(), failure::Error> {
    let mut runtime = Runtime::new().unwrap();
    let app = match tdns {
        Tdns::Query(opt) => {
            if opt.common.tcp {
                run_query(runtime.handle(), TcpOpen, opt)?
            } else {
                run_query(runtime.handle(), UdpOpen, opt)?
            }
        }
        Tdns::Update(opt) => {
            if opt.common.tcp {
                run_update(runtime.handle(), TcpOpen, opt)?
            } else {
                run_update(runtime.handle(), UdpOpen, opt)?
            }
        }
    };
    runtime.block_on(app)
}

fn main() {
    let tdns = Tdns::from_args();
    let rc = match run(tdns) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("error: {}", e);
            1
        }
    };
    std::process::exit(rc);
}