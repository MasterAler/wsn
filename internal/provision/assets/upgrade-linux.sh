#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "run this upgrade as root" >&2
  exit 1
fi

new_binary=${1:?usage: upgrade-linux.sh /path/to/wsn-client EXPECTED_SHA256}
expected=${2:?usage: upgrade-linux.sh /path/to/wsn-client EXPECTED_SHA256}
actual=$(sha256sum "$new_binary" | awk '{print $1}')
test "$actual" = "$expected" || { echo "SHA-256 mismatch" >&2; exit 1; }

systemctl stop wsn-client.service
cp -p /opt/wsn/wsn-client /opt/wsn/wsn-client.previous
install -m 0755 "$new_binary" /opt/wsn/wsn-client
if ! systemctl start wsn-client.service; then
  cp -p /opt/wsn/wsn-client.previous /opt/wsn/wsn-client
  systemctl start wsn-client.service
  echo "upgrade failed; previous binary restored" >&2
  exit 1
fi
sleep 2
if ! systemctl is-active --quiet wsn-client.service; then
  cp -p /opt/wsn/wsn-client.previous /opt/wsn/wsn-client
  systemctl restart wsn-client.service
  echo "upgrade failed health check; previous binary restored" >&2
  exit 1
fi

echo "WSN client upgraded"
