# tdns-update

A dynamic DNS updater and update checker.

Note that `tdns-update` is currently in its initial development phase,
and hasn't even been deployed in earnest by its author. The usual
caveats apply. If you're still interested, read on for more
information of what is currently working, and what is planned.

`tdns-update` updates and/or monitors an entry in a DNS zone. The
updating functionality is currently an _extremely_ limited subset of
what the `nsupdate` utility from the ISC BIND provides, but providing
both updates and monitoring in a single native executable is novel, at
least to the author's knowledge. There are doubtlessly numerous shell
scripts around that provide similar functionality, with varying
degrees of sophistication. `tdns-update` aims to its job correctly and
efficiently, taking no shortcuts.

With a single `tnds-update` invocation, you can both perform a DNS
update operation, and wait for all the authoritative nameservers in
the zone to provide the updated records.

`tdns-update` is implemented in Rust, taking advantage of the terrific
[`trust-dns`] DNS client library, and uses a single-threaded,
non-blocking runtime. Translated from developer speak, this means that
`tdns-udpate` should be very light on system resources, and cope well
even with unreasonably large tasks, such as monitoring a record in a
zone that is served by hundreds of authoritative nameservers.

# Missing features

Without those, `tdns-update` cannot function reliably, or can be
considered not doing the job properly:

- [X] DNS query retries.
- [X] Use system resolver by default. This currently only works on
      systems that have `/etc/resolv.conf`.
- [ ] Probe all addresses an `NS` entry resolves to.
- [ ] IPv6 support; the code is largely agnostic of IP address family,
      but IPv6 support has not yet been actively worked on.

# Planned features

- [X] TCP support -- currently, only UDP-based DNS is supported.
- [ ] Useful DNS Update functionality. Currently, the functionality is
      very in a very limited proof-of-concept state.
- [ ] A test suite that checks the application logic against a mocked
      "DNS server".

## Installation

As `tdns-update` is written in Rust, you need a [Rust toolchain]. Rust
1.37 or newer is required. To obtain the latest release from
[crates.io], use:

```sh
cargo install tdns-update
```

Alternatively, you can run it directly from the source checkout:

```sh
cargo run -- --help
```

To install from locally checked-out source, use `cargo install --path
.`, which will end up installing the executable in
`~/.cargo/bin/tdns-update`, which should already be in your `PATH`
environment variable, if you followed the Rust toolchain installations
instructions.

### Static build

For deployment to a Linux target, an attractive option is to create a
statically linked binary using Rust's MUSL target. This will result in
a completely standalone binary, which depends only on the Linux
kernel's system call ABI.

```sh
# If you haven't installed the MUSL target already, let's do that now:
rustup target add x86_64-unknown-linux-musl
# Build against the MUSL libc target
cargo build --target x86_64-unknown-linux-musl --release
# Let's check it's really a static binary
file target/x86_64-unknown-linux-musl/release/tdns-update \
  | grep -q 'statically linked' || echo "nope"
```

# Example use case

This is the scenario which prompted the development of `tdns-update`.

When obtaining TLS certificates from letsencrypt using the [DNS-01
protocol], it is necessary to ensure that letsencrypt is only told to
verify the challenge after it can be reliably retrieved. With
secondary DNS servers, it can take a while until the update is
completely rolled out to all of them. `tdns-update` can be used as
part of the hook script to deploy the letsencrypt challenge to DNS.

[Rust toolchain]: https://www.rust-lang.org/tools/install
[`trust-dns`]: https://github.com/bluejekyll/trust-dns
[DNS-01 protocol]: https://letsencrypt.org/docs/challenge-types/
