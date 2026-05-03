#!/usr/bin/env bash
# S4 — Persistence (cron entry + SSH key implant) inside a pot.
#
# Authenticates to the pot using the per-pot credentials (extracted
# at orchestration time from the events table or from the controller
# state, since the cred is not stored in plaintext). Installs a
# cron entry and an authorized_keys line. Records four discrete
# actions on stdout for the harness; the controller should emit one
# `auth` (success) and several `command` events per the agent's
# observers.

set -euo pipefail

POT_IP="${POT_IP:?POT_IP required}"
POT_USER="${POT_USER:?POT_USER required}"
POT_PASS="${POT_PASS:?POT_PASS required}"
ATTACKER_IP="${ATTACKER_IP:-10.10.42.200}"
TAG="${1:-S4}"

emit() {
    local kind="$1" action="$2"
    local now; now="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
    printf '{"time":"%s","kind":"%s","source":"%s","target":"%s","action":"%s","tag":"%s"}\n' \
        "$now" "$kind" "$ATTACKER_IP" "$POT_IP" "$action" "$TAG"
}

run_remote() {
    sshpass -p "$POT_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        "$POT_USER@$POT_IP" "$1"
}

emit auth login
run_remote "true"

emit command cron-install
run_remote 'echo "* * * * * /tmp/.s4-marker" | crontab -'

emit command ssh-key-implant
run_remote 'mkdir -p ~/.ssh && echo "ssh-ed25519 AAAAS4MARKER" >> ~/.ssh/authorized_keys'

emit command verify
run_remote 'crontab -l | grep -c s4-marker; grep -c S4MARKER ~/.ssh/authorized_keys'
