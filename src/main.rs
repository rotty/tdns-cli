use std::{
    convert::TryFrom,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use failure::format_err;
use structopt::StructOpt;
use tokio::runtime::current_thread::Runtime;
use trust_dns::rr;

use tdns_update::{
    record::{RecordSet, RsData},
    update::Update,
    update::{Mode, Settings},
    util, TcpOpen, UdpOpen,
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
    /// Domain to monitor.
    domain: rr::Name,
    /// Entry to monitor.
    entry: rr::Name,
    /// Expected query response.
    expected: RsData,
    /// Excluded IP address.
    #[structopt(long)]
    exclude: Option<IpAddr>,
    /// Do not perform the update.
    #[structopt(long)]
    no_op: bool,
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

impl TryFrom<Opt> for Settings {
    type Error = failure::Error;

    fn try_from(opt: Opt) -> Result<Self, Self::Error> {
        let resolver = opt
            .resolver
            .or_else(util::get_system_resolver)
            .ok_or_else(|| {
                format_err!("could not obtain resolver address from operating system")
            })?;
        let entry = opt.entry.append_name(&opt.domain);
        Ok(Settings {
            resolver,
            expected: RecordSet::new(entry.clone(), opt.expected),
            domain: opt.domain,
            entry,
            exclude: opt.exclude.into_iter().collect(),
            interval: Duration::from_secs(opt.interval.unwrap_or(1)),
            timeout: Duration::from_secs(opt.timeout.unwrap_or(60)),
            verbose: opt.verbose,
            mode: match (!opt.no_op, !opt.no_wait) {
                (true, true) => Mode::UpdateAndMonitor,
                (true, false) => Mode::Update,
                (false, true) => Mode::Monitor,
                (false, false) => {
                    return Err(format_err!(concat!(
                        "Both --no-op and --no-wait specified.\n",
                        "If you really wanted that, why not just use the POSIX `true` utility?"
                    )))
                }
            },
        })
    }
}

fn run(opt: Opt) -> Result<(), failure::Error> {
    let mut runtime = Runtime::new().unwrap();
    let tcp = opt.tcp;
    let settings = Settings::try_from(opt)?;
    let app = if tcp {
        Update::new(runtime.handle(), TcpOpen, settings)?.run()
    } else {
        Update::new(runtime.handle(), UdpOpen, settings)?.run()
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
