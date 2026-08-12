#!/bin/sh
# WSN_* values are supplied by /etc/wsn/network.env, which is generated per
# client by wsnctl and cannot be followed statically.
# shellcheck source=/dev/null
set -eu

. /etc/wsn/network.env

configure_dns() {
  [ -n "${WSN_DNS:-}" ] || return 0
  [ -n "${WSN_SEARCH:-}" ] || return 0
  if ! command -v resolvectl >/dev/null 2>&1; then
    echo "resolvectl is unavailable; corporate names will not resolve through WSN" >&2
    return 0
  fi
  # A leading '~' makes each domain routing-only, so corporate names go to the
  # corporate resolver while every other lookup keeps using the resolvers the
  # machine already had. Without this the link would capture all resolution.
  routing=''
  for domain in $WSN_SEARCH; do
    routing="$routing ~$domain"
  done
  # Programming DNS is best effort. A host where systemd-resolved is installed
  # but not the active resolver would otherwise fail this unit under `set -e`,
  # taking the whole tunnel down instead of just corporate name resolution.
  # shellcheck disable=SC2086 # routing is a deliberately split domain list
  if resolvectl dns "$WSN_DEVICE" "$WSN_DNS" && resolvectl domain "$WSN_DEVICE" $routing; then
    return 0
  fi
  echo "could not program corporate DNS on $WSN_DEVICE; the tunnel is up but corporate names will not resolve" >&2
}

up() {
  modprobe tun
  if ip link show "$WSN_DEVICE" >/dev/null 2>&1; then
    echo "interface $WSN_DEVICE already exists; refusing to replace it" >&2
    exit 1
  fi
  ip tuntap add dev "$WSN_DEVICE" mode tap user wsn group wsn
  trap 'ip link del dev "$WSN_DEVICE" 2>/dev/null || true' EXIT
  # The overlay carries IPv4 only; leaving IPv6 enabled just floods the
  # segment with link-local traffic nothing answers.
  sysctl -qw "net.ipv6.conf.$WSN_DEVICE.disable_ipv6=1" >/dev/null 2>&1 || true
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
  configure_dns
  trap - EXIT
}

down() {
  for route in $WSN_ROUTES; do
    ip route del "$route" via "$WSN_GATEWAY" dev "$WSN_DEVICE" metric 5 2>/dev/null || true
  done
  # Per-link resolver settings are discarded with the interface itself.
  ip link del dev "$WSN_DEVICE" 2>/dev/null || true
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 <up|down>" >&2; exit 2 ;;
esac
