#!/usr/bin/env bash
# T5 — Background traffic for FPR measurement.
#
# Runs forever (until killed by the harness). Once a minute, from
# the "monitoring" production host, issues benign probes against
# every pot in the deployment: ping, TCP open-and-close on 22, HTTP
# HEAD on 80. Any event the controller emits with source =
# 10.10.42.12 during this window counts as a false positive.

set -euo pipefail

NET="${EVAL_NETWORK:-10.10.42.0/24}"
MON_HOST="${MON_HOST:-10.10.42.12}"
SLEEP_S="${SLEEP_S:-60}"

# Discover currently-deployed pot IPs once per minute via the API.
# The probe loop runs locally on the monitoring host, so we ssh into
# it for each tick. The harness sets MON_SSH_USER/MON_SSH_PASS.

while :; do
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        "$MON_SSH_USER@$MON_HOST" \
        bash -s -- "$NET" <<'REMOTE' || true
NET="$1"
for ip in $(nmap -sL -n "$NET" 2>/dev/null | awk '/Nmap scan report/ {print $5}'); do
    ping -c 1 -W 1 "$ip" >/dev/null 2>&1 || true
    timeout 1 bash -c "exec 3</dev/tcp/$ip/22" 2>/dev/null || true
    curl -sS -o /dev/null --max-time 1 "http://$ip/" || true
done
REMOTE
    sleep "$SLEEP_S"
done
