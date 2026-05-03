#!/usr/bin/env bash
# A5 — Lateral SMB from compromised pot to production file server.
set -euo pipefail
: "${POT_IP:?}"; : "${POT_USER:?}"; : "${POT_PASS:?}"
PROD_FS_IP="${PROD_FS_IP:-10.10.42.11}"
sshpass -p "$POT_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    "$POT_USER@$POT_IP" \
    "timeout 8 smbclient -N -L //$PROD_FS_IP/ || true"
