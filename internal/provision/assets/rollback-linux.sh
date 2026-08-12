#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "run this rollback as root" >&2
  exit 1
fi
test -f /opt/wsn/wsn-client.previous || { echo "no previous binary is available" >&2; exit 1; }

systemctl stop wsn-client.service
current=/opt/wsn/wsn-client.rollback
mv /opt/wsn/wsn-client "$current"
mv /opt/wsn/wsn-client.previous /opt/wsn/wsn-client
mv "$current" /opt/wsn/wsn-client.previous
systemctl start wsn-client.service
echo "WSN client rolled back"
