#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "run this installer as root" >&2
  exit 1
fi

source_state=${1:?usage: install.sh /path/to/extracted/server-bundle}
script_dir=$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)

for file in server.json relay.crt relay.key; do
  test -f "$source_state/$file" || { echo "missing $source_state/$file" >&2; exit 1; }
done
test -f "$script_dir/.env" || { echo "copy .env.example to .env and configure it first" >&2; exit 1; }

install -d -m 0700 "$script_dir/state"
install -m 0600 "$source_state/server.json" "$script_dir/state/server.json"
install -m 0644 "$source_state/relay.crt" "$script_dir/state/relay.crt"
install -m 0600 "$source_state/relay.key" "$script_dir/state/relay.key"
chown 65532:65532 "$script_dir/state/server.json"

cd "$script_dir"
docker compose config --quiet
docker compose pull
docker compose up -d --remove-orphans --force-recreate
docker compose ps
