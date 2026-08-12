#!/bin/sh
set -eu

. /etc/wsn/network.env

up() {
  modprobe tun
  if ip link show "$WSN_DEVICE" >/dev/null 2>&1; then
    echo "interface $WSN_DEVICE already exists; refusing to replace it" >&2
    exit 1
  fi
  ip tuntap add dev "$WSN_DEVICE" mode tap user wsn group wsn
  trap 'ip link del dev "$WSN_DEVICE" 2>/dev/null || true' EXIT
  ip link set dev "$WSN_DEVICE" address "$WSN_MAC"
  ip addr add "$WSN_ADDRESS" dev "$WSN_DEVICE"
  ip link set dev "$WSN_DEVICE" mtu 1500 up
  for route in $WSN_ROUTES; do
    if ip route show "$route" | grep -q .; then
      echo "route $route already exists; refusing to replace it" >&2
      exit 1
    fi
    ip route add "$route" via "$WSN_GATEWAY" dev "$WSN_DEVICE" metric 5
  done
  trap - EXIT
}

down() {
  for route in $WSN_ROUTES; do
    ip route del "$route" via "$WSN_GATEWAY" dev "$WSN_DEVICE" metric 5 2>/dev/null || true
  done
  ip link del dev "$WSN_DEVICE" 2>/dev/null || true
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 <up|down>" >&2; exit 2 ;;
esac
