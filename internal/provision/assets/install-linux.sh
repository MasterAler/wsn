#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "run this installer as root" >&2
  exit 1
fi

bundle_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

systemctl stop wsn-client.service 2>/dev/null || true
systemctl stop wsn-gateway.service 2>/dev/null || true
systemctl stop wsn-net.service 2>/dev/null || true

if [ ! -f "$bundle_dir/gateway.env" ]; then
  systemctl disable wsn-gateway.service 2>/dev/null || true
  if [ -f /etc/wsn/ip_forward.previous ]; then
    previous_forward=$(cat /etc/wsn/ip_forward.previous)
    sysctl -w "net.ipv4.ip_forward=$previous_forward" >/dev/null
  fi
  rm -f /etc/wsn/gateway.env /etc/wsn/ip_forward.previous /etc/sysctl.d/90-wsn-gateway.conf
  rm -f /usr/local/libexec/wsn-gateway /etc/systemd/system/wsn-gateway.service
fi

if ! getent group wsn >/dev/null 2>&1; then
  groupadd --system wsn
fi
if ! getent passwd wsn >/dev/null 2>&1; then
  useradd --system --gid wsn --home-dir /nonexistent --shell /usr/sbin/nologin wsn
fi

install -d -m 0755 /opt/wsn /etc/wsn /usr/local/libexec
install -m 0755 "$bundle_dir/wsn-client" /opt/wsn/wsn-client
install -o root -g wsn -m 0640 "$bundle_dir/client.json" /etc/wsn/client.json
install -o root -g wsn -m 0640 "$bundle_dir/client.key" /etc/wsn/client.key
install -m 0644 "$bundle_dir/relay-ca.crt" /etc/wsn/relay-ca.crt
install -m 0644 "$bundle_dir/network.env" /etc/wsn/network.env
install -m 0755 "$bundle_dir/wsn-net.sh" /usr/local/libexec/wsn-net
install -m 0644 "$bundle_dir/wsn-net.service" /etc/systemd/system/wsn-net.service
install -m 0644 "$bundle_dir/wsn-client.service" /etc/systemd/system/wsn-client.service

if [ -f "$bundle_dir/gateway.env" ]; then
  command -v iptables >/dev/null 2>&1 || { echo "iptables is required for a gateway" >&2; exit 1; }
  install -m 0600 "$bundle_dir/gateway.env" /etc/wsn/gateway.env
  install -m 0755 "$bundle_dir/wsn-gateway.sh" /usr/local/libexec/wsn-gateway
  install -m 0644 "$bundle_dir/wsn-gateway.service" /etc/systemd/system/wsn-gateway.service
  . /etc/wsn/gateway.env
  /opt/wsn/wsn-client -config /etc/wsn/client.json -check-network gateway -egress "$WSN_EGRESS"
  if [ ! -f /etc/wsn/ip_forward.previous ]; then
    cat /proc/sys/net/ipv4/ip_forward >/etc/wsn/ip_forward.previous
    chmod 0600 /etc/wsn/ip_forward.previous
  fi
  printf 'net.ipv4.ip_forward = 1\n' >/etc/sysctl.d/90-wsn-gateway.conf
  sysctl --system >/dev/null
fi

if [ ! -f "$bundle_dir/gateway.env" ]; then
  /opt/wsn/wsn-client -config /etc/wsn/client.json -check-network client
fi

systemctl daemon-reload
systemctl enable --now wsn-net.service
if [ -f /etc/wsn/gateway.env ]; then
  systemctl enable --now wsn-gateway.service
fi
systemctl enable --now wsn-client.service

echo "WSN installation complete"
