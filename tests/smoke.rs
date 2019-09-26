use std::time::{Duration, Instant};

use futures::{future, prelude::*};
use tdns_update::{
    record::RecordSet,
    update::{Operation, Settings, Update},
};
use tokio::{runtime::current_thread::Runtime, timer::Delay};
use trust_dns::rr;

mod mock;
use mock::{parse_rdata, ZoneEntries};

const TIMEOUT: Duration = Duration::from_millis(10);

fn test_settings(operation: Operation, monitor: bool, expected: &str) -> Settings {
    Settings {
        zone: "example.org".parse().unwrap(),
        entry: "foo.example.org".parse().unwrap(),
        rset: RecordSet::new(
            "foo.example.org".parse().unwrap(),
            expected.parse().unwrap(),
        ),
        interval: TIMEOUT / 100,
        timeout: TIMEOUT,
        verbose: true,
        operation,
        monitor,
        ..Default::default()
    }
}

fn mock_dns(master_data: ZoneEntries) -> (mock::Open, mock::Handle<mock::Server>) {
    let rec_data: &[_] = &[
        (
            "example.org",
            "SOA",
            "sns.dns.icann.org. noc.dns.icann.org. 2019090512 7200 3600 1209600 3600",
        ),
        ("example.org", "NS", "a.iana-servers.net."),
        ("example.org", "NS", "b.iana-servers.net."),
        ("a.iana-servers.net", "A", "199.43.135.53"),
        ("b.iana-servers.net", "A", "199.43.133.53"),
        ("sns.dns.icann.org", "A", "192.0.32.162"),
    ];
    let rec_addr = "127.0.0.1:53".parse().unwrap();
    let master_addr = "192.0.32.162:53".parse().unwrap();
    let mut mock = mock::Open::default();
    mock.add_server(rec_addr, rec_data).unwrap();
    let master = mock.add_server(master_addr, master_data).unwrap();
    (mock, master)
}

fn mock_dns_fixed(
    master_data: ZoneEntries,
    auth1_data: ZoneEntries,
    auth2_data: ZoneEntries,
) -> mock::Open {
    let (mut dns, _) = mock_dns(master_data);
    let auth1_addr = "199.43.135.53:53".parse().unwrap();
    let auth2_addr = "199.43.133.53:53".parse().unwrap();
    dns.add_server(auth1_addr, auth1_data).unwrap();
    dns.add_server(auth2_addr, auth2_data).unwrap();
    dns
}

fn mock_dns_shared(master_data: ZoneEntries) -> (mock::Open, mock::Handle<mock::Zone>) {
    let (mut dns, master) = mock_dns(master_data);
    let auth1_addr = "199.43.135.53:53".parse().unwrap();
    let auth2_addr = "199.43.133.53:53".parse().unwrap();
    let master = master.lock().unwrap();
    dns.add_shared(auth1_addr, master.zone());
    dns.add_shared(auth2_addr, master.zone());
    (dns, master.zone())
}

fn mock_dns_independent(master_data: ZoneEntries) -> (mock::Open, mock::Handle<mock::Zone>) {
    let (mut dns, _) = mock_dns(master_data);
    let auth1_addr = "199.43.135.53:53".parse().unwrap();
    let auth2_addr = "199.43.133.53:53".parse().unwrap();
    let slave = dns.add_server(auth1_addr, master_data).unwrap();
    let slave = slave.lock().unwrap();
    dns.add_shared(auth2_addr, slave.zone());
    (dns, slave.zone())
}

#[test]
fn test_monitor_match() {
    let mut runtime = Runtime::new().unwrap();
    let (dns, _) = mock_dns_shared(&[("foo.example.org", "A", "192.168.1.1")]);
    let update = Update::new(
        runtime.handle(),
        dns,
        test_settings(Operation::None, true, "A:192.168.1.1"),
    )
    .unwrap()
    .run();
    runtime.block_on(update).unwrap();
}

#[test]
fn test_monitor_mismatch() {
    let mut runtime = Runtime::new().unwrap();
    let dns = mock_dns_fixed(
        &[("foo.example.org", "A", "192.168.1.1")],
        &[("foo.example.org", "A", "192.168.1.1")],
        &[("foo.example.org", "A", "192.168.1.2")],
    );
    let update = Update::new(
        runtime.handle(),
        dns,
        test_settings(Operation::None, true, "A:192.168.1.1"),
    )
    .unwrap()
    .run();
    let result = runtime.block_on(update);
    assert!(result.is_err()); // TODO: check for timeout error, specifically
}

#[test]
fn test_create_immediate() {
    let mut runtime = Runtime::new().unwrap();
    let (dns, _) = mock_dns_shared(&[("foo.example.org", "A", "192.168.1.1")]);
    let update = Update::new(
        runtime.handle(),
        dns,
        test_settings(Operation::Create, true, "A:192.168.1.2"),
    )
    .unwrap()
    .run();
    runtime.block_on(update).unwrap();
}

#[test]
fn test_create_delayed() {
    let mut runtime = Runtime::new().unwrap();
    let (dns, zone) = mock_dns_independent(&[("foo.example.org", "A", "192.168.1.1")]);
    let update = Update::new(
        runtime.handle(),
        dns,
        test_settings(Operation::Create, true, "A:192.168.1.2"),
    )
    .unwrap()
    .run();
    let updated = rr::Record::from_rdata(
        "foo.example.org".parse().unwrap(),
        0,
        parse_rdata("A", "192.168.1.2").unwrap(),
    );
    let update_auth = Delay::new(Instant::now() + TIMEOUT / 2)
        .map(|_| {
            let mut zone = zone.lock().unwrap();
            zone.update(&updated);
        })
        .map_err(Into::into);
    runtime
        .block_on(future::join_all(vec![update, Box::new(update_auth)]))
        .unwrap();
}

#[test]
fn test_delete() {
    let mut runtime = Runtime::new().unwrap();
    let (dns, _) = mock_dns_shared(&[("foo.example.org", "A", "192.168.1.1")]);
    let update = Update::new(
        runtime.handle(),
        dns,
        test_settings(Operation::Delete, true, "A:192.168.1.1"),
    )
    .unwrap()
    .run();
    runtime.block_on(update).unwrap();
}
