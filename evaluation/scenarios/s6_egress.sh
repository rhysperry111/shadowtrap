#!/usr/bin/env bash
# S6 — Outbound egress attempts from a compromised pot.
#
# Three discrete actions: TCP connect to a public IP, DNS query to
# attacker resolver, ICMP echo to attacker host. All three should be
# dropped at the host firewall (containment A1/A2/A3) and emit
# `egress_blocked` events from the drop watcher.

set -euo pipefail

POT_IP="${POT_IP:?POT_IP required}"
POT_USER="${POT_USER:?POT_USER required}"
POT_PASS="${POT_PASS:?POT_PASS required}"
ATTACKER_IP="${ATTACKER_IP:-10.10.42.200}"
PUBLIC_IP="${PUBLIC_IP:-198.51.100.7}"   # any unreachable IP works
DNS_TARGET="${DNS_TARGET:-198.51.100.53}"
TAG="${1:-S6}"

emit() {
    local action="$1"
    local now; now="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
    printf '{"time":"%s","kind":"egress","source":"%s","target":"%s","action":"%s","tag":"%s"}\n' \
        "$now" "$ATTACKER_IP" "$POT_IP" "$action" "$TAG"
}

run_remote() {
    sshpass -p "$POT_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 "$POT_USER@$POT_IP" "$1"
}

emit "outbound-tcp-$PUBLIC_IP"
run_remote "timeout 5 bash -c 'exec 3</dev/tcp/$PUBLIC_IP/443 || true'"

emit "outbound-dns-$DNS_TARGET"
run_remote "timeout 5 dig @$DNS_TARGET example.com +short || true"

emit "icmp-tunnel-$ATTACKER_IP"
run_remote "timeout 5 ping -c 5 $ATTACKER_IP || true"
