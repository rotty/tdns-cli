use std::time::Duration;

use tdns_update::{
    record::{RecordSet, RsData},
    update::{Settings, Update},
};
use tokio::runtime::current_thread::Runtime;

mod mock;

/// This is a basic excercise of the whole happy path.
#[test]
fn test_smoke() {
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
    let auth_data = &[("foo.example.org", "A", "192.168.1.1")];
    let open = mock::Open::new(vec![
        (rec_addr, rec_data),
        (master_addr, empty),
        (auth1_addr, auth_data),
        (auth2_addr, auth_data),
    ])
    .unwrap();
    let mut runtime = Runtime::new().unwrap();
    let update = Update::new(
        runtime.handle(),
        open,
        Settings {
            zone: "example.org".parse().unwrap(),
            entry: "foo.example.org".parse().unwrap(),
            expected: RecordSet::new(
                "foo.example.org".parse().unwrap(),
                RsData::A(
                    vec!["192.168.1.1"]
                        .into_iter()
                        .map(str::parse)
                        .collect::<Result<_, _>>()
                        .unwrap(),
                ),
            ),
            interval: Duration::from_nanos(100),
            timeout: Duration::from_millis(10),
            verbose: true,
            ..Default::default()
        },
    )
    .unwrap()
    .run();
    runtime.block_on(update).unwrap();
}
