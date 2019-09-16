# tdns-update

A dynamic DNS update checker, with aspirations to do the updating
itself.

`tdns-update` monitors an entry in a DNS zone, checking all the
authoritative nameservers in the zone, and waits until the records for
that entry reach a specified expected state.

After initiating a dynamic DNS update request, if you need to know
when the update has propagated to all authoritative nameservers for
the affected zone, this is exactly the job `tdns-update` can do for
you.

`tdns-update` is implemented in Rust, taking advantage of the terrific
[`trust-dns`] DNS client library, and uses a single-threaded,
non-blocking runtime. Translated from developer speak, this means that
`tdns-udpate` should be very light on system resources, and cope well
even with unreasonably large tasks, such as monitoring a record in a
zone that is served by hundreds of authoritative nameservers.

Note that `tdns-update` is currently in its initial development phase,
and hasn't even been deployed by its author. The usual caveats apply.

# Missing features

Without those, `tdns-update` cannot function reliably, or can be
considered not doing the job properly:

- [X] DNS query retries.
- [ ] Probe all addresses an `NS` entry resolves to.
- [ ] IPv6 support.

# Planned features

- [ ] TCP support -- currently, only UDP-based DNS is supported.
- [ ] DNS Update functionality. Since [`trust-dns`], the DNS client
      library used by `tdns-update` implements this mechanism,
      including update functionality should be not too hard to add.

## Installation

As `tdns-update` is written in Rust, you need a [Rust toolchain]. Rust
1.37 or newer is required.

You can run it directly from the source checkout:

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
