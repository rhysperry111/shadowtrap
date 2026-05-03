#!/usr/bin/env bash
# S2 — SSH credential stuffing.
#
# Hydra against a single pot picked from the deployment. Each
# attempted login is emitted as a JSONL action; the agent's sshd
# parser should produce an `auth` event per attempt.

set -euo pipefail

POT_IP="${POT_IP:?POT_IP required (target pot, e.g. 10.10.42.18)}"
USERS_FILE="${USERS_FILE:-scenarios/data/users.txt}"
PASS_FILE="${PASS_FILE:-scenarios/data/passwords.txt}"
ATTACKER_IP="${ATTACKER_IP:-10.10.42.200}"
TAG="${1:-S2}"

# Hydra emits one ATTEMPT line per try; we capture them and emit JSONL.
hydra -L "$USERS_FILE" -P "$PASS_FILE" -t 4 -V "ssh://$POT_IP" 2>&1 \
    | awk -v attacker="$ATTACKER_IP" -v target="$POT_IP" -v tag="$TAG" '
        /\[ATTEMPT\]/ {
            cmd="date -u +%Y-%m-%dT%H:%M:%S.%3NZ"; cmd | getline t; close(cmd)
            user=""; for (i=1; i<=NF; i++) if ($i == "login:") user=$(i+1)
            printf "{\"time\":\"%s\",\"kind\":\"auth\",\"source\":\"%s\",\"target\":\"%s\",\"user\":\"%s\",\"tag\":\"%s\"}\n", t, attacker, target, user, tag
        }
    '
