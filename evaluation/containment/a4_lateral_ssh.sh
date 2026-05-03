#!/usr/bin/env bash
# A4 — Lateral SSH from compromised pot to peer pot.
set -euo pipefail
: "${POT_IP:?}"; : "${POT_USER:?}"; : "${POT_PASS:?}"; : "${PEER_POT_IP:?}"
sshpass -p "$POT_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    "$POT_USER@$POT_IP" \
    "timeout 8 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=4 root@$PEER_POT_IP true || true"
