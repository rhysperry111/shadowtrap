#!/usr/bin/env bash
# S1 — TCP sweep against the evaluation /24.
#
# Each TCP connect against an unused-IP-turned-pot should produce a
# `connection` event from sshd / apache2 within ~1 s. The script
# emits one JSONL action per probed port-IP pair on stdout for the
# T3 harness to correlate against the events table.

set -euo pipefail

NET="${EVAL_NETWORK:-10.10.42.0/24}"
PORTS="${EVAL_PORTS:-22,80,445,3306,3389,5432}"
ATTACKER_IP="${ATTACKER_IP:-10.10.42.200}"
TAG="${1:-S1}"

# Run nmap; capture per-host port-state lines.
nmap -sT -p"$PORTS" -oG - --max-rate 200 "$NET" 2>/dev/null \
    | awk -v attacker="$ATTACKER_IP" -v tag="$TAG" '
        /^Host/ {
            ip=$2
            for (i=1; i<=NF; i++) {
                if ($i ~ /\/open\//) {
                    split($i, p, "/"); port=p[1]
                    cmd="date -u +%Y-%m-%dT%H:%M:%S.%3NZ"
                    cmd | getline t; close(cmd)
                    printf "{\"time\":\"%s\",\"kind\":\"connection\",\"source\":\"%s\",\"target\":\"%s\",\"port\":%s,\"tag\":\"%s\"}\n", t, attacker, ip, port, tag
                }
            }
        }
    '
