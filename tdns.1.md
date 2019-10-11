% TDNS(1) tnds Manual
% Andreas Rottmann
% October, 2019

# NAME

tnds -  DNS client multitool

# SYNOPSIS

__tdns query__ [*options*] *dns-name*

__tdns update__ [*options*] *dns-name* *rs-data*

# DESCRIPTION

__tdns__ is a DNS client, aiming to provide a select subset of the
functionality provided by the `dig` and `nsupdate` commands from the
ISC bind suite.

# TDNS COMMANDS

__tdns-query__(1)
:   Construct and submit DNS queries, and display the results.

__tdns-update__(1)
:   Update DNS zones via the "DNS UPDATE" mechanism specified in
    RFC 2136. Authenticated updates are possible via TSIG (RFC 2845).

# EXAMPLES

Query for IPv4 and IPv6 addresses associated with a DNS name:

    tdns query -t A,AAAA example.org

Create a fresh DNS entry, using a key file to sign the update request
with a shared secret:

    tdns update --create foo.example.org A:10.1.2.3 --key-file secret.key
