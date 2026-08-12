#!/bin/sh
set -eu

. /etc/wsn/gateway.env

FILTER_CHAIN=WSN_FORWARD
NAT_CHAIN=WSN_POSTROUTING

delete_jump() {
  table=$1
  chain=$2
  target=$3
  while iptables -w -t "$table" -C "$chain" -j "$target" 2>/dev/null; do
    iptables -w -t "$table" -D "$chain" -j "$target"
  done
}

down() {
  delete_jump filter FORWARD "$FILTER_CHAIN"
  delete_jump nat POSTROUTING "$NAT_CHAIN"
  iptables -w -F "$FILTER_CHAIN" 2>/dev/null || true
  iptables -w -X "$FILTER_CHAIN" 2>/dev/null || true
  iptables -w -t nat -F "$NAT_CHAIN" 2>/dev/null || true
  iptables -w -t nat -X "$NAT_CHAIN" 2>/dev/null || true
}

up() {
  down
  iptables -w -N "$FILTER_CHAIN"
  iptables -w -t nat -N "$NAT_CHAIN"

  iptables -w -A "$FILTER_CHAIN" -i "$WSN_EGRESS" -o "$WSN_DEVICE" -d "$WSN_OVERLAY" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  for destination in $WSN_DESTINATIONS; do
    iptables -w -A "$FILTER_CHAIN" -i "$WSN_DEVICE" -o "$WSN_EGRESS" -s "$WSN_OVERLAY" -d "$destination" -j ACCEPT
    iptables -w -t nat -A "$NAT_CHAIN" -o "$WSN_EGRESS" -s "$WSN_OVERLAY" -d "$destination" -j MASQUERADE
  done
  iptables -w -A "$FILTER_CHAIN" -i "$WSN_DEVICE" -s "$WSN_OVERLAY" -j REJECT
  iptables -w -A "$FILTER_CHAIN" -j RETURN
  iptables -w -t nat -A "$NAT_CHAIN" -j RETURN

  iptables -w -I FORWARD 1 -j "$FILTER_CHAIN"
  iptables -w -t nat -I POSTROUTING 1 -j "$NAT_CHAIN"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 <up|down>" >&2; exit 2 ;;
esac
