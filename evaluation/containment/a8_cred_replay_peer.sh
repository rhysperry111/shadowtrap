#!/usr/bin/env bash
# A8 — Credential replay against a peer pot.
# Each pot has a unique credential set so the replay must reject;
# capture the auth-fail line and append to cred-replay.log.
set -euo pipefail
: "${POT_USER:?}"; : "${POT_PASS:?}"; : "${PEER_POT_IP:?}"
EVIDENCE="${EVIDENCE_DIR:-$(dirname "$0")/../evidence}"
LOG="$EVIDENCE/cred-replay.log"
mkdir -p "$EVIDENCE"

echo "[$(date -u --iso=seconds)] A8 attempt $POT_USER@$PEER_POT_IP" >> "$LOG"
sshpass -p "$POT_PASS" ssh \
    -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o PreferredAuthentications=password \
    "$POT_USER@$PEER_POT_IP" 'true' >> "$LOG" 2>&1 || \
    echo "[$(date -u --iso=seconds)] A8 reject $POT_USER@$PEER_POT_IP" >> "$LOG"
