#!/usr/bin/env bash
# A1 — Outbound TCP from compromised pot to public IP.
# Expectation: dropped at host firewall; drop watcher emits event.
set -euo pipefail
: "${POT_IP:?}"; : "${POT_USER:?}"; : "${POT_PASS:?}"
PUBLIC_IP="${PUBLIC_IP:-198.51.100.7}"
sshpass -p "$POT_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    "$POT_USER@$POT_IP" "for i in 1 2 3 4 5; do timeout 2 bash -c 'exec 3</dev/tcp/$PUBLIC_IP/443' || true; done"
