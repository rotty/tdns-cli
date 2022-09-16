#!/bin/sh

set -e

container=$(buildah from alpine:3.20)
buildah run "$container" -- apk add --no-cache pdns pdns-backend-sqlite3
buildah copy "$container" pdns.conf /etc/pdns/pdns.conf
buildah run "$container" -- mkdir /var/lib/pdns
buildah run "$container" -- chown pdns: /var/lib/pdns
buildah run --user pdns:pdns "$container" -- sqlite3 /var/lib/pdns/pdns.sqlite3 < pdns-schema-4.7.0.schema-sqlite.sql
buildah run "$container" -- pdnsutil create-zone example.org
buildah copy "$container" example.org.zone /tmp/example.org.zone
buildah run "$container" -- pdnsutil load-zone example.org /tmp/example.org.zone
buildah run "$container" -- rm /tmp/example.org.zone
buildah config --cmd "/usr/sbin/pdns_server" "$container"
buildah config --port 53/tcp --port 53/udp "$container"
