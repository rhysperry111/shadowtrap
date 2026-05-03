#!/usr/bin/env bash
# A2 — Outbound DNS to attacker resolver.
set -euo pipefail
: "${POT_IP:?}"; : "${POT_USER:?}"; : "${POT_PASS:?}"
RES="${DNS_TARGET:-198.51.100.53}"
sshpass -p "$POT_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    "$POT_USER@$POT_IP" "for i in 1 2 3 4 5; do timeout 2 dig @$RES example.com +short || true; done"
