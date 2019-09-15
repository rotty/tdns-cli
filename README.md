# tdns-update

A dynamic DNS update checker, with aspirations to do the updating
itself.

`tdns-update` monitors an entry in a DNS zone, checking all the
authoritative nameservers in the zone, and waits until the records for
that entry reach a specified expected state.

After initiating a dynamic DNS update request, if you need to know
when the update has propagated to all authoritative nameservers for
the affected zone, this `tdns-update` can do that job for you.

Note that `tdns-update` is currently in its initial development phase,
and hasn't even been deployed by its author. The usual caveats apply.

# Missing features

Without those, `tdns-update` cannot function reliably, or can be
considered not doing the job properly:

- [ ] DNS query retries.
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
