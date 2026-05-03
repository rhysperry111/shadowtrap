#!/usr/bin/env bash
# A9 — Credential replay against the production jumphost.
set -euo pipefail
: "${POT_USER:?}"; : "${POT_PASS:?}"
PROD="${PROD_HOST_IP:-10.10.42.10}"
EVIDENCE="${EVIDENCE_DIR:-$(dirname "$0")/../evidence}"
LOG="$EVIDENCE/cred-replay.log"
mkdir -p "$EVIDENCE"

echo "[$(date -u --iso=seconds)] A9 attempt $POT_USER@$PROD" >> "$LOG"
sshpass -p "$POT_PASS" ssh \
    -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o PreferredAuthentications=password \
    "$POT_USER@$PROD" 'true' >> "$LOG" 2>&1 || \
    echo "[$(date -u --iso=seconds)] A9 reject $POT_USER@$PROD" >> "$LOG"
