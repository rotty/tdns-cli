use std::{
    pin::Pin,
    time::{Duration, Instant},
};

use futures::{prelude::*, stream::FuturesUnordered};
use tdns_cli::{
    record::RecordSet,
    update::{monitor_update, perform_update, Expectation, Monitor, Operation, Update},
    Backend,
};
use tokio::{runtime::current_thread::Runtime, timer::delay};
use trust_dns_client::rr;

mod mock;
use mock::{parse_rdata, MockBackend, ZoneEntries};

const TIMEOUT: Duration = Duration::from_millis(10);

fn monitor_settings(expected: &str) -> Monitor {
    let rset = RecordSet::new(
        "foo.example.org".parse().unwrap(),
        expected.parse().unwrap(),
    );
    Monitor {
        zone: "example.org".parse().unwrap(),
        entry: "foo.example.org".parse().unwrap(),
        expectation: if rset.is_empty() {
            Expectation::Empty(rset.record_type())
        } else {
            Expectation::Is(rset)
        },
        exclude: Default::default(),
        interval: TIMEOUT / 100,
        timeout: TIMEOUT,
        verbose: true,
    }
}

fn update_settings(operation: Operation) -> Update {
    Update {
        zone: "example.org".parse().unwrap(),
        server: None,
        operation,
        tsig_key: None,
        ttl: 300,
    }
}

fn mock_dns(master_data: ZoneEntries) -> (MockBackend, mock::Handle<mock::Server>) {
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
    let mut mock = MockBackend::default();
    mock.add_server(rec_addr, rec_data).unwrap();
    let master = mock.add_server(master_addr, master_data).unwrap();
    (mock, master)
}

fn mock_dns_fixed(
    master_data: ZoneEntries,
    auth1_data: ZoneEntries,
    auth2_data: ZoneEntries,
) -> MockBackend {
    let (mut dns, _) = mock_dns(master_data);
    let auth1_addr = "199.43.135.53:53".parse().unwrap();
    let auth2_addr = "199.43.133.53:53".parse().unwrap();
    dns.add_server(auth1_addr, auth1_data).unwrap();
    dns.add_server(auth2_addr, auth2_data).unwrap();
    dns
}

fn mock_dns_shared(master_data: ZoneEntries) -> (MockBackend, mock::Handle<mock::Zone>) {
    let (mut dns, master) = mock_dns(master_data);
    let auth1_addr = "199.43.135.53:53".parse().unwrap();
    let auth2_addr = "199.43.133.53:53".parse().unwrap();
    let master = master.lock().unwrap();
    dns.add_shared(auth1_addr, master.zone());
    dns.add_shared(auth2_addr, master.zone());
    (dns, master.zone())
}

fn mock_dns_independent(master_data: ZoneEntries) -> (MockBackend, mock::Handle<mock::Zone>) {
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
    let (mut dns, _) = mock_dns_shared(&[("foo.example.org", "A", "192.168.1.1")]);
    let resolver = dns.open(runtime.handle(), "127.0.0.1:53".parse().unwrap());
    let monitor = monitor_update(
        runtime.handle(),
        dns,
        resolver,
        monitor_settings("A:192.168.1.1"),
    );
    runtime.block_on(monitor).unwrap();
}

#[test]
fn test_monitor_mismatch() {
    let mut runtime = Runtime::new().unwrap();
    let mut dns = mock_dns_fixed(
        &[("foo.example.org", "A", "192.168.1.1")],
        &[("foo.example.org", "A", "192.168.1.1")],
        &[("foo.example.org", "A", "192.168.1.2")],
    );
    let resolver = dns.open(runtime.handle(), "127.0.0.1:53".parse().unwrap());
    let monitor = monitor_update(
        runtime.handle(),
        dns,
        resolver,
        monitor_settings("A:192.168.1.1"),
    );
    let result = runtime.block_on(monitor);
    assert!(result.is_err()); // TODO: check for timeout error, specifically
}

#[test]
fn test_create_immediate() {
    let mut runtime = Runtime::new().unwrap();
    let (mut dns, _) = mock_dns_shared(&[("foo.example.org", "A", "192.168.1.1")]);
    let resolver = dns.open(runtime.handle(), "127.0.0.1:53".parse().unwrap());
    let update = perform_update(
        runtime.handle(),
        dns.clone(),
        resolver.clone(),
        update_settings(Operation::Create(RecordSet::new(
            "foo.example.org".parse().unwrap(),
            "A:192.168.1.2".parse().unwrap(),
        ))),
    );
    let monitor = monitor_update(
        runtime.handle(),
        dns,
        resolver,
        monitor_settings("A:192.168.1.2"),
    );
    runtime.block_on(update.and_then(|_| monitor)).unwrap();
}

#[test]
fn test_create_delayed() {
    let mut runtime = Runtime::new().unwrap();
    let (mut dns, zone) = mock_dns_independent(&[("foo.example.org", "A", "192.168.1.1")]);
    let resolver = dns.open(runtime.handle(), "127.0.0.1:53".parse().unwrap());
    let update = perform_update(
        runtime.handle(),
        dns,
        resolver,
        update_settings(Operation::create(
            "foo.example.org".parse().unwrap(),
            "A:192.168.1.2".parse().unwrap(),
        )),
    );
    async fn update_auth(zone: mock::Handle<mock::Zone>) -> Result<(), failure::Error> {
        delay(Instant::now() + TIMEOUT / 2).await;
        let updated = rr::Record::from_rdata(
            "foo.example.org".parse().unwrap(),
            0,
            parse_rdata("A", "192.168.1.2").unwrap(),
        );
        let mut zone = zone.lock().unwrap();
        zone.update(&updated);
        Ok(())
    }
    let mut parallel = FuturesUnordered::new();
    parallel.push(Box::pin(update) as Pin<Box<dyn Future<Output = Result<(), failure::Error>>>>);
    parallel.push(Box::pin(update_auth(zone)));
    runtime.block_on(parallel.try_collect::<Vec<_>>()).unwrap();
}

#[test]
fn test_delete() {
    let mut runtime = Runtime::new().unwrap();
    let (mut dns, _) = mock_dns_shared(&[("foo.example.org", "A", "192.168.1.1")]);
    let resolver = dns.open(runtime.handle(), "127.0.0.1:53".parse().unwrap());
    let update = perform_update(
        runtime.handle(),
        dns.clone(),
        resolver.clone(),
        update_settings(Operation::delete(
            "foo.example.org".parse().unwrap(),
            "A:192.168.1.1".parse().unwrap(),
        )),
    );
    let monitor = monitor_update(runtime.handle(), dns, resolver, monitor_settings("A"));
    runtime.block_on(update.and_then(|_| monitor)).unwrap();
}
