% TDNS-UPDATE(1) tnds-update Manual
% Andreas Rottmann
% October, 2019

# NAME

tnds-update -  DNS update client (RFC 2136)

# SYNOPSIS

__tdns update__ [*options*] *dns-name* *rs-data*

# DESCRIPTION

__tdns update__ is an alternative to the `nsupdate` utility which is
distributed as part of the ISC BIND suite. It is currently not as
general as `nsupdate`, but provides the additional feature of
(optionally) ensuring that the DNS update has propagated to all
authoritative nameservers of a domain. This feature is helpful when
implementing challenge-response protocols such as the DNS-01 variant
of the letsencrypt ACME protocol, as it ensures that when
__tdns update__ exits successfully, any subsequent query to any of the
authoritative nameservers will see the updated records.

Furthermore, __tnds update__ provides a command-line interface that
intends to cover all basic use-cases, like creating, deleting and
updating a DNS resource record set, while __nsupdate__ requires a
simple "script". This should make using __tdns update__ a bit more
straightforward for these basic use-cases, compared to constructing a
script on the fly and piping it into __nsupdate__.

# OPTIONS

## Mode of operation

__tdns update__ allows combining a nameserver update (__\--create__,
__\--delete__) with optional monitoring, i.e. waiting for the specified
update to happen. If no update action is specified, monitoring will
still happen, unless turned off with __\--no-wait__.

\--no-op
:   Does not perform an update, but still monitors the zone's
    nameservers for the given data to appear. This is the default if no
    action is specified. If __\--no-op__ is combined with __\--no-wait__,
    __tdns update__ will behave like a heavyweight implementation of the
    classic `true`(1) command.

\--create
:   Creates *dns-name*, with the contents given by
    *rs-data*. *Prerequisite*: No RRset for the name of the type
    specified by *rs-data* may already exist.

\--append
:   Adds the records implied by *dns-name* and *rs-data* to the zone.

\--delete
:   Deletes records matching the given *dns-name* and *rs-data*
    arguments. Note that without *rs-data* argument, all records
    matching *dns-name* will be deleted. To delete all records of a
    specific type, a bare type may be used as *rs-data* argument.

\--no-wait
:   Per default, __tdns update__ will monitor the authoritative
    nameservers of the updated zone and wait until the update is visible
    on all of them. With this option, __tnds-update__ terminates
    immediately after the update operation, not performing any
    monitoring.

## Tunables

\--zone=*zone*
:   Specify the DNS zone to update; the zone's SOA record will be used
    to determine the primary master, unless __\--server__ is used. If not
    given, the zone is derived from *dns-name* by stripping the initial
    label; e.g. for `foo.example.org`, the derived zone will be
    `example.org`.

\--server=*server*
:   Primary master to send updates to; if not specified, it will be
    determined from the SOA record of the updated zone. The given
    *server* may either be an IP address or a hostname, optionally
    including a port.

\--resolver=*address*
:   Resolver to use for recursive queries. If not specified, the
    resolver name will be determined based on the contents of
    `/etc/resolv.conf`, using the first `nameserver` entry given
    therein.

\--ttl=*seconds*
:   Set the TTL, in seconds, for any records created due to an
    update. If not specified, a default of 3600 (i.e., one hour) is
    used.

\--key=*name:algorithm:base64-secret*, \--key=*name*
:   Use the specified secret to sign the update request with TSIG
    signature. TSIG allows the server to validate the update request
    using a shared secret. The components of a full key specification
    are as follows:

    - *name* is the key name, which must match between server and
      client. It needs to conform to DNS name syntax.
    - *algorithm* is the name of the HMAC algorithm used for
      signatures. The following algorithms are supported: `hmac-sha224`,
      `hmac-sha256`, `hmac-sha384`, `hmac-sha512`. Older algorithms
      relying on SHA1 or MD5 hashes have been intentionally left out.
    - *base64-secret* is the shared secret in base64-encoded form.

    Note that using a full key specification is *not* recommended for
    production use, as the secret may leak via the process table and
    shell history. Use __\--key-file__ instead, and consider tightening
    the permissions on the key file as appropriate. The second __\--key__
    form, where only *name* is given can be used to select a key from a
    key file containing multiple keys.

\--key-file=*file*
:   Read the TSIG key from a file. The file must contain lines which
    each in the same format as the argument to the __\--key__ option,
    i.e. *name:algorithm:base64-secret*. If __\--key-file__ is used
    without __\--key__, the first key in the file will be used, but it
    may also be combined with the name-only form of __\--key__, in which
    case the *algorithm* and *base64-secret* will be taken from the
    file, and the key name will be used to to select the appropriate
    line from the file.

\--exclude=*address*
:   Exclude *address*, which must be an IPv4 or IPv6 address from
    monitoring. If an `NS` record resolves to this IP address, it is not
    monitored. This is useful for excluding the primary master, i.e.,
    the server the update requests are sent to from monitoring, for
    example if it is not reachable via its public IP address from the
    machine __tdns update__ is run on.

\--tcp
:   Use TCP for all DNS requests.

\--verbose
:   Increase verbosity. If enabled, __tdns update__ will print
    informational messages during execution.

# RECORD SET SYNTAX

A resource record set (RRset), as specified by RFC 2136, is a set of
DNS resource records (RRs) that have the same name, class, and
type. For instance, all `A` records for the DNS name `foo.example.org`
form an RRset. In today's use of DNS, only class `IN` is in common
use, so only that class is currently supported by __tdns update__.

__tdns update__ is currently restricted to a single RRset, with a
specific type and name. The RRset data, including the RRset type, is
given via the *rs-data* arguments. The general syntax for *rs-data* is
uniform, although the syntax of the data portion is type-dependent;
for instance `AAAA` RRsets require all data items to be valid IPv6
addresses.

The *rs-data* argument is written as its type, a colon, and a data
item for each record. The data items are separated by commas. For
example, `A:192.168.1.1,10.0.0.1` denotes an RRset of type `A`, with
the given two IPv4 addresses.

The following types of RRsets are supported:

`A`
: Each data item must be an IPv4 address.

`AAAA`
: Each data item must be an IPv6 address.

`TXT`
: Each data item must be valid UTF-8 string.

# EXAMPLES

The following will update `foo.example.org` with an IPv4 and IPv6
address, deleting the old entries first:

    tdns update --delete --no-wait foo.example.org A
    tdns update --create foo.example.org A:10.1.2.3
    tnds-update --append foo.example.org AAAA:dead:beef::1234

# BUGS

- The set of supported record types is quite small; other commonly
  used record types, such as `CNAME`, `PTR`, `MX` and `NS` are going
  to be added at the author's whim, or due to contributions.

- The notation for `TXT` record data is excessively restrictive
  compared to what is allowed according to RFC 1464:

  - Only a single data item may be specified per record.
  - There is no support for quoting, so items containing commas (the
    item separator) cannot be represented.

  A future version of __tdns update__ should lift these restrictions.

- __tdns update__ currently can only handle a small class of updates
  that are possible via __nsupdate__ scripts; it is planned to extend
  the command line interface to support more common operations, such
  as deleting the RRsets before creating them anew.

  Another possible future direction is to implement taking update
  instructions from a file, akin to nsupdate scripts, allowing for
  capabilities like:

  - Update multiple DNS entries for a zone in a single update query.
  - Update and monitor multiple zones in a single invocation, which is
    a feature beyond __nsupdate__'s current capabilities.
