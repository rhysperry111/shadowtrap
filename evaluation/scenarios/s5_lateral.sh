#!/usr/bin/env bash
# S5 — Lateral movement attempts from a compromised pot.
#
# Authenticates to the source pot, then attempts SSH to a peer pot
# and SMB to the production file server. Both should be dropped at
# the host firewall (containment.json A4/A5) and emit
# `containment / egress_blocked` events.

set -euo pipefail

POT_IP="${POT_IP:?POT_IP required}"
POT_USER="${POT_USER:?POT_USER required}"
POT_PASS="${POT_PASS:?POT_PASS required}"
PEER_POT_IP="${PEER_POT_IP:?PEER_POT_IP required}"
PROD_FS_IP="${PROD_FS_IP:-10.10.42.11}"
ATTACKER_IP="${ATTACKER_IP:-10.10.42.200}"
TAG="${1:-S5}"

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

emit "lateral-ssh-peer-$PEER_POT_IP"
run_remote "timeout 8 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=4 root@$PEER_POT_IP true || true"

emit "lateral-smb-prod-$PROD_FS_IP"
run_remote "timeout 8 smbclient -N -L //$PROD_FS_IP/ || true"
