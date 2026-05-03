#!/usr/bin/env bash
# A7 — SSH key implant within pot lifetime; must be discarded on
# TTL rebuild. Same shape as A6.
set -euo pipefail
: "${POT_IP:?}"; : "${POT_USER:?}"; : "${POT_PASS:?}"
: "${SHADOWTRAP_API:?}"; : "${SHADOWTRAP_API_KEY:?}"; : "${DEPLOYMENT_ID:?}"

remote() {
    sshpass -p "$POT_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        "$POT_USER@$POT_IP" "$1"
}

echo "[A7] implanting key"
remote 'mkdir -p ~/.ssh && echo "ssh-ed25519 AAAAA7MARKER attacker@kali" >> ~/.ssh/authorized_keys'
present=$(remote 'grep -c A7MARKER ~/.ssh/authorized_keys' || echo 0)
[[ "$present" -ge 1 ]] && echo "WITHIN_LIFETIME=true" || echo "WITHIN_LIFETIME=false"

echo "[A7] forcing TTL rebuild"
curl -sS -X PUT "${SHADOWTRAP_API}/api/settings/pots/deployments/${DEPLOYMENT_ID}" \
    -H "api_key: ${SHADOWTRAP_API_KEY}" -H 'Content-Type: application/json' \
    -d "{\"ttl_minutes\":1}" >/dev/null

sleep 90

new_ip=$(curl -sS "${SHADOWTRAP_API}/api/info/pots" \
    -H "api_key: ${SHADOWTRAP_API_KEY}" \
    | jq -r ".pots[] | select(.deployment==\"${DEPLOYMENT_ID}\") | .ip" | head -n1)
[[ -z "$new_ip" ]] && { echo "PASS=false"; exit 1; }

still=$(sshpass -p "$POT_PASS" ssh -o StrictHostKeyChecking=no \
    "$POT_USER@$new_ip" 'grep -c A7MARKER ~/.ssh/authorized_keys 2>/dev/null' || echo 0)
[[ "$still" == 0 ]] && echo "PASS=true" || echo "PASS=false"
