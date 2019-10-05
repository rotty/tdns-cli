# tdns-update

A dynamic DNS updater and update checker, using the mechanism
described in RFC 2136.

Note that `tdns-update` is currently in its initial development phase,
and hasn't even been deployed in earnest by its author. The usual
caveats apply. If you're still interested, read on for more
information of what is currently working, and what is planned.

`tdns-update` updates and/or monitors an entry in a DNS zone. The
updating functionality is currently a very limited subset of what the
`nsupdate` utility from the ISC BIND provides, but providing both
updates and monitoring in a single native executable is novel, at
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

## Documentation

The documentation for `tdns-update` comes in the form of [man
page](./tnds-update.1.md). The markdown file can be turned in to troff
format for viewing with the `man` command using [pandoc]. Note that to
the markdown source is tailored toward producing good output when fed
through pandoc, and will not be rendered nicely on github or alike,
and is not ideal to read in plain, either.

You can generate the manpage using the included `Makefile`, and view
the man page using the Unix `man` command:

```sh
make tdns-update.1 && man -l tnds-update.1
```

You can also find a pandoc HTML rendering of the manpage
[online](https://r0tty.org/software/tnds-update.1.html).

# Missing features

Without those, `tdns-update` cannot function reliably, or can be
considered not doing the job properly:

- [X] DNS query retries.
- [X] Use system resolver by default. This currently only works on
      systems that have `/etc/resolv.conf`.
- [ ] Probe all addresses an `NS` entry resolves to.
- [ ] IPv6 support; the code is largely agnostic of IP address family,
      but IPv6 support has not yet been actively worked on.
- [X] Support for TSIG, which provides authenticated updates using a
      shared secret.
- [ ] Allow for the TSIG key to be provided in a file, to prevent
      leakage via `ps` and shell history.

# Planned features

- [X] TCP support -- currently, only UDP-based DNS is supported.
- [ ] Support more DNS update variants. The current functionality
      should suffice to implement the letencrypt DNS-01 challenge
      protocol, but is not yet sufficient for a general-purpose
      tool. At least adding a record to an RRset and deleting all
      RRsets for a DNS name are missing to cover the basics.
- [ ] To become a viable replacement for `nsupdate`, a more elaborate
      way for describing the update. similar to the `nsupdate`
      "scripts" is needed; adapting the command-line interface is not
      suitable for more complex update operations.
- [ ] Once a mechanism for describing an update in some kind of DSL is
      added, it should be quite easy to allow updating multiple zones
      concurrently in a single run. This functionality is probably not
      that useful in practice, but who knows...
- [X] A test suite that checks the application logic against a mocked
      "DNS server". This is implemented in basic form, but coverage is
      currently quite limited.

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
[pandoc]: https://pandoc.org/

# License

Copyright © 2019 Andreas Rottmann

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or (at
your option) any later version.

This program is distributed in the hope that it will be useful, but
*WITHOUT ANY WARRANTY*; without even the implied warranty of
*MERCHANTABILITY* or *FITNESS FOR A PARTICULAR PURPOSE*. See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, see <https://www.gnu.org/licenses>.

## Additional permission under GNU GPL version 3 section 7

If you modify this Program, or any covered work, by linking or
combining it with OpenSSL (or a modified version of that library),
containing parts covered by the terms of OpenSSL License, the
licensors of this Program grant you additional permission to convey
the resulting work. Corresponding Source for a non-source form of such
a combination shall include the source code for the parts of OpenSSL
used as well as that of the covered work.

# Contributions

Unless explicitly indicated otherwise, any contribution intentionally
submitted for inclusion in this crate:

- Will be licensed under the GNU GPL version 3.0, or
  later, with the additional permissions listed above.
- The contributor additionally grants the crate maintainer the right
  to re-license parts or all of the crate's code, including the
  contribution, to the dual MIT/Apache-2.0 license. This is provision
  is for the case that some part of the crate's code turns out to be
  of general utility, such that it would benefit from being split out
  and being given a more liberal, non-copyleft license.
