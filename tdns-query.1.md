% TDNS-UPDATE(1) tnds-query Manual
% Andreas Rottmann
% October, 2019

# NAME

tnds-query -  DNS query client

# SYNOPSIS

__tdns query__ [*options*] *dns-name*

# DESCRIPTION

__tdns query__ provides a subset of the functionality found in the
`dig` utility which is distributed as part of the ISC BIND suite. Its
functionality is currently quite limited compared to `dig`, but
extending it to be a reasonable replacement for common usage is
planned.

# OPTIONS

\--resolver=*address*
:   DNS server to send queries to. If not specified, the resolver name
    will be determined based on the contents of `/etc/resolv.conf`,
    using the first `nameserver` entry given therein.

\--tcp
:   Use TCP for all DNS requests.

# EXAMPLES

Query for IPv4 and IPv6 addresses associated with a DNS name:

    tdns query -t A,AAAA example.org

# BUGS

- Only the record data is shown, similar to `dig +short`.
- Only record data of for types `A`, `AAAA` and `TXT` are displayed
  properly.
