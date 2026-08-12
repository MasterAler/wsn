#!/bin/sh
# Apply a refreshed server.json (clients added or revoked) without restarting
# the relay. Established sessions that are still authorized keep running; a
# revoked identity is disconnected immediately.
#
# Use install.sh instead when the relay image or the TLS certificate changed.
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "run this reload as root" >&2
  exit 1
fi

source_state=${1:?usage: reload.sh /path/to/extracted/server-bundle}
script_dir=$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)

test -f "$source_state/server.json" || { echo "missing $source_state/server.json" >&2; exit 1; }
test -d "$script_dir/state" || { echo "run install.sh first" >&2; exit 1; }

install -m 0600 "$source_state/server.json" "$script_dir/state/server.json"
chown 65532:65532 "$script_dir/state/server.json"

cd "$script_dir"
docker compose kill -s SIGHUP relay
echo "relay reloaded; confirm with: docker compose logs --tail=20 relay"
