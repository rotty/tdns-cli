# tdns [![Build Status]][travis]

[Build Status]: https://api.travis-ci.org/rotty/tdns-cli.svg?branch=master
[travis]: https://travis-ci.org/rotty/tdns-cli

A DNS client command-line tool, with aspirations to become a swiss
army knife when it has grown up.

`tdns` aims to grow into a replacement for the `nsupdate` and `dig`
commands distributed as part of the ISC bind suite, adding features
such as propagation checking for updates and a more convenient (and
"standard") command-line interface.

`tdns` is implemented in Rust, taking advantage of the terrific
[`trust-dns`] DNS client library, and uses a single-threaded,
non-blocking runtime. Translated from developer speak, this means that
`tdns-udpate` should be very light on system resources, and cope well
even with unreasonably large tasks, such as monitoring a record in a
zone that is served by hundreds of authoritative nameservers.

Note that `tdns` is currently in its initial development phase. The
usual caveats apply. If you're still interested, read on for more
information of what is currently working, and what is planned.

## Installation

As `tdns` is written in Rust, you need a [Rust toolchain]. Rust 1.37
or newer is required. To obtain the latest release from [crates.io],
use:

```sh
cargo install tdns-cli
```

Alternatively, you can run it directly from the source checkout, note
that the master branch is using `async/await`, which requires Rust
1.39, currently in beta; so you need the beta toolchain.

```sh
cargo +beta run -- --help
```

To install from locally checked-out source, use `cargo +beta install
--path .`, which will end up installing the executable in
`~/.cargo/bin/tdns`, which should already be in your `PATH`
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
file target/x86_64-unknown-linux-musl/release/tdns \
  | grep -q 'statically linked' || echo "nope"
```

### Documentation

The documentation for the `tdns` and its subcommands are provided in
the form of Unix man pages, rendered from markdown source files, which
can be turned in to troff format for viewing with the `man` command
using [pandoc]. Note that to the markdown sources are tailored toward
producing good output when fed through pandoc, and will not be
rendered that nicely on github or alike, and is not ideal to read in
plain, either.

You can generate the manpages using the included `Makefile`, and view
the man page using the Unix `man` command:

```sh
make man
man -l tdns.1
man -l tnds-query.1
man -l tnds-update.1
```

HTML renderings of the manpages are also created when running `make`,
these are also available online:

- [tdns.1](https://r0tty.org/software/tnds.1.html), providing an
  overview.
- [tdns-query.1](https://r0tty.org/software/tnds-query.1.html),
  documenting the `tdns query` subcommand.
- [tdns-update.1](https://r0tty.org/software/tnds-update.1.html),
  documenting the `tdns update` subcommand.

## Available subcommands

### tdns query

This subcommand can be used as a partial substitute for `dig +short`;
extending the functionality is planned.

### tdns update

A dynamic DNS updater and update checker, using the mechanism
described in RFC 2136.

`tdns update` updates and/or monitors an entry in a DNS zone. The
updating functionality is currently a limited subset of what the
`nsupdate` utility from the ISC BIND provides, but providing both
updates and monitoring in a single native executable is novel, at
least to the author's knowledge. There are doubtlessly numerous shell
scripts around that provide similar functionality, with varying
degrees of sophistication. `tdns update` aims to its job correctly and
efficiently, taking no shortcuts.

With a single `tnds update` invocation, you can both perform a DNS
update operation, and wait for all the authoritative nameservers in
the zone to provide the updated records.

#### Missing features

Without those, `tdns update` cannot function reliably, or can be
considered not doing the job properly:

- [ ] If no `--resolver` option is provided, make use of all the
      resolvers specified in `/etc/resolv.conf`, not just the first
      one.
- [ ] Probe all addresses an `NS` entry resolves to.
- [ ] IPv6 support; the code is largely agnostic of IP address family,
      but IPv6 support has not yet been actively worked on.

#### Planned features

- [ ] To become a full replacement for `nsupdate`, a more elaborate
      way for describing the update, similar to the `nsupdate`
      "scripts" is needed; adapting the command-line interface is not
      suitable for more complex update operations.
- [ ] Once a mechanism for describing an update in some kind of DSL is
      added, it should be quite easy to allow updating multiple zones
      concurrently in a single run. This functionality is probably not
      that useful in practice, but who knows...
- [ ] Increase the test coverage of the test suite; the infrastructure
      and some basic tests are present, but coverage is quite limited
      currently.

#### Example use case

This is the scenario which prompted the development of `tdns update`.

When obtaining TLS certificates from letsencrypt using the [DNS-01
protocol], it is necessary to ensure that letsencrypt is only told to
verify the challenge after it can be reliably retrieved. With
secondary DNS servers, it can take a while until the update is
completely rolled out to all of them. `tdns update` can be used as
part of the hook script to deploy the letsencrypt challenge to DNS.

## License

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

### Additional permission under GNU GPL version 3 section 7

If you modify this Program, or any covered work, by linking or
combining it with OpenSSL (or a modified version of that library),
containing parts covered by the terms of OpenSSL License, the
licensors of this Program grant you additional permission to convey
the resulting work. Corresponding Source for a non-source form of such
a combination shall include the source code for the parts of OpenSSL
used as well as that of the covered work.

## Contributions

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

[Rust toolchain]: https://www.rust-lang.org/tools/install
[`trust-dns`]: https://github.com/bluejekyll/trust-dns
[DNS-01 protocol]: https://letsencrypt.org/docs/challenge-types/
[pandoc]: https://pandoc.org/
[crates.io]: https://crates.io
