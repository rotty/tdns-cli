use std::time::Duration;

use tdns_update::{
    record::RecordSet,
    update::{Settings, Update},
};
use tokio::runtime::current_thread::Runtime;

mod mock;

fn test_settings(expected: &str) -> Settings {
    Settings {
        zone: "example.org".parse().unwrap(),
        entry: "foo.example.org".parse().unwrap(),
        expected: RecordSet::new(
            "foo.example.org".parse().unwrap(),
            expected.parse().unwrap(),
        ),
        interval: Duration::from_nanos(100),
        timeout: Duration::from_millis(10),
        verbose: true,
        ..Default::default()
    }
}

fn mock_dns(data1: &[(&str, &str, &str)], data2: &[(&str, &str, &str)]) -> mock::Open {
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
    let empty: &[_] = &[];
    let rec_addr = "127.0.0.1:53".parse().unwrap();
    let master_addr = "192.0.32.162:53".parse().unwrap();
    let auth1_addr = "199.43.135.53:53".parse().unwrap();
    let auth2_addr = "199.43.133.53:53".parse().unwrap();
    mock::Open::new(vec![
        (rec_addr, rec_data),
        (master_addr, empty),
        (auth1_addr, data1),
        (auth2_addr, data2),
    ])
    .unwrap()
}

#[test]
fn test_smoke_match() {
    let mut runtime = Runtime::new().unwrap();
    let update = Update::new(
        runtime.handle(),
        mock_dns(
            &[("foo.example.org", "A", "192.168.1.1")],
            &[("foo.example.org", "A", "192.168.1.1")],
        ),
        test_settings("A:192.168.1.1"),
    )
    .unwrap()
    .run();
    runtime.block_on(update).unwrap();
}

#[test]
fn test_smoke_mismatch() {
    let mut runtime = Runtime::new().unwrap();
    let update = Update::new(
        runtime.handle(),
        mock_dns(&[("foo.example.org", "A", "192.168.1.1")],
                 &[("foo.example.org", "A", "192.168.1.2")]),
        test_settings("A:192.168.1.1"),
    )
    .unwrap()
    .run();
    let result = runtime.block_on(update);
    assert!(result.is_err()); // TODO: check for timeout error
}
