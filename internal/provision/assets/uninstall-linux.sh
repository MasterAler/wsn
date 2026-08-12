#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "run this uninstaller as root" >&2
  exit 1
fi

systemctl disable --now wsn-client.service 2>/dev/null || true
systemctl disable --now wsn-gateway.service 2>/dev/null || true
systemctl disable --now wsn-net.service 2>/dev/null || true

if [ -f /etc/wsn/ip_forward.previous ]; then
  previous_forward=$(cat /etc/wsn/ip_forward.previous)
  sysctl -w "net.ipv4.ip_forward=$previous_forward" >/dev/null
fi

rm -f /etc/systemd/system/wsn-client.service /etc/systemd/system/wsn-gateway.service /etc/systemd/system/wsn-net.service
rm -f /usr/local/libexec/wsn-net /usr/local/libexec/wsn-gateway /etc/sysctl.d/90-wsn-gateway.conf
rm -rf /opt/wsn /etc/wsn
systemctl daemon-reload

echo "WSN removed; the dedicated wsn user/group were retained"
