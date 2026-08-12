#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
certificate="$script_dir/state/relay.crt"
test -f "$certificate" || { echo "relay certificate is not installed" >&2; exit 1; }

if ! openssl x509 -in "$certificate" -checkend 2592000 -noout; then
  echo "WSN relay certificate expires within 30 days; rotate it with wsnctl" >&2
  exit 1
fi

openssl x509 -in "$certificate" -noout -enddate
