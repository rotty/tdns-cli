use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use data_encoding::BASE64;
use failure::format_err;
use futures::{future, StreamExt};
use structopt::StructOpt;
use tokio::runtime::current_thread::Runtime;
use trust_dns::{proto::error::ProtoError, rr};
use trust_dns_resolver::error::{ResolveError, ResolveErrorKind};

use tdns_cli::{
    query::{self, perform_query, Query},
    record::{RecordSet, RsData},
    tsig,
    update::{monitor_update, perform_update, Expectation, Monitor, Operation, Update},
    util, Backend, RuntimeHandle, TcpBackend, UdpBackend,
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

// This is just so that `structopt` does not treat options of this type as
// taking multiple arguments.
type RTypes = Vec<rr::RecordType>;

fn parse_rtypes(s: &str) -> Result<RTypes, ProtoError> {
    let s = s.to_uppercase();
    util::parse_comma_separated(&s)
}

#[derive(StructOpt)]
struct QueryOpt {
    #[structopt(flatten)]
    common: CommonOpt,
    entry: rr::Name,
    #[structopt(long = "type", short = "t", parse(try_from_str = parse_rtypes))]
    record_types: Option<RTypes>,
    #[structopt(long = "fmt", short = "f")]
    display_format: Option<query::DisplayFormat>,
}

impl QueryOpt {
    fn get_display_format(
        display_format: Option<query::DisplayFormat>,
        query_types: &[rr::RecordType],
    ) -> query::DisplayFormat {
        use query::DisplayFormat;
        use rr::RecordType::*;
        display_format.unwrap_or_else(move || {
            if (query_types.len() == 1 && query_types[0] != ANY)
                || query_types.iter().all(|&rtype| rtype == A || rtype == AAAA)
            {
                DisplayFormat::Short
            } else {
                DisplayFormat::Zone
            }
        })
    }

    fn to_query(&self) -> Result<Query, failure::Error> {
        let record_types = self
            .record_types
            .as_ref()
            .map(|cs| cs.to_vec())
            .unwrap_or_else(|| vec![rr::RecordType::A]);
        Ok(Query {
            entry: self.entry.clone(),
            display_format: Self::get_display_format(self.display_format, &record_types),
            record_types,
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
                        BASE64.decode(data.as_bytes())?,
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
                BASE64.decode(data.as_bytes())?,
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

fn open_resolver<D: Backend + 'static>(
    runtime: RuntimeHandle,
    mut dns: D,
    addr: Option<SocketAddr>,
) -> Result<D::Resolver, ResolveError> {
    if let Some(addr) = addr {
        Ok(dns.open_resolver(runtime, addr))
    } else {
        Ok(dns.open_system_resolver(runtime)?)
    }
}

async fn run_update<D: Backend + 'static>(
    runtime: RuntimeHandle,
    dns: D,
    opt: UpdateOpt,
) -> Result<(), failure::Error> {
    let resolver = open_resolver(runtime.clone(), dns.clone(), opt.common.resolver)?;
    if let Some(update) = opt.to_update()? {
        perform_update(runtime.clone(), dns.clone(), resolver.clone(), update).await?;
    }
    if let Some(monitor) = opt.to_monitor()? {
        monitor_update(runtime, dns, resolver, monitor).await?;
    }
    Ok(())
}

async fn run_query<D: Backend + 'static>(
    runtime: RuntimeHandle,
    dns: D,
    opt: QueryOpt,
) -> Result<(), failure::Error> {
    let resolver = open_resolver(runtime.clone(), dns.clone(), opt.common.resolver)?;
    let query = opt.to_query()?;
    let (n_failed, total) = perform_query(resolver, query.clone())
        .fold((0_usize, 0_usize), |(n_failed, total), item| {
            let mut stdout = std::io::stdout();
            let success = match item {
                Ok(records) => {
                    for record in records {
                        query::write_record(&mut stdout, &record, query.display_format).unwrap();
                        stdout.write_all(b"\n").unwrap();
                    }
                    true
                }
                Err(e) => match e.kind() {
                    ResolveErrorKind::NoRecordsFound { .. } => true,
                    _ => {
                        eprintln!("error response for query: {}", e);
                        false
                    }
                },
            };
            future::ready((n_failed + if success { 0 } else { 1 }, total + 1))
        })
        .await;
    if n_failed > 0 {
        return Err(format_err!("{}/{} queries failed", n_failed, total,));
    }
    Ok(())
}

async fn run(runtime: RuntimeHandle, tdns: Tdns) -> Result<(), failure::Error> {
    match tdns {
        Tdns::Query(opt) => {
            if opt.common.tcp {
                run_query(runtime, TcpBackend, opt).await?
            } else {
                run_query(runtime, UdpBackend, opt).await?
            }
        }
        Tdns::Update(opt) => {
            if opt.common.tcp {
                run_update(runtime, TcpBackend, opt).await?
            } else {
                run_update(runtime, UdpBackend, opt).await?
            }
        }
    }
    Ok(())
}

fn main() {
    let mut runtime = Runtime::new().unwrap();
    let tdns = Tdns::from_args();
    let rc = match runtime.block_on(run(runtime.handle(), tdns)) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Error: {}", e);
            1
        }
    };
    std::process::exit(rc);
}
