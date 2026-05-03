#!/usr/bin/env bash
# A6 — Cron persistence within pot lifetime, must be discarded on
# TTL rebuild. The script:
#   1. Plants the cron entry.
#   2. Confirms it is present (PASS=true if grep matches).
#   3. Sets the deployment's TTL to 1 minute via the API to force a
#      rebuild, waits 90s, then re-checks (PASS=true if absent).
# Output line `PASS=true` consumed by t4_containment.py.
set -euo pipefail
: "${POT_IP:?}"; : "${POT_USER:?}"; : "${POT_PASS:?}"
: "${SHADOWTRAP_API:?}"; : "${SHADOWTRAP_API_KEY:?}"; : "${DEPLOYMENT_ID:?}"

remote() {
    sshpass -p "$POT_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        "$POT_USER@$POT_IP" "$1"
}

echo "[A6] planting cron"
remote 'echo "* * * * * /tmp/.a6-marker" | crontab -'
present=$(remote 'crontab -l 2>/dev/null | grep -c a6-marker' || echo 0)
[[ "$present" -ge 1 ]] && echo "WITHIN_LIFETIME=true" || echo "WITHIN_LIFETIME=false"

echo "[A6] forcing TTL rebuild via API"
curl -sS -X PUT "${SHADOWTRAP_API}/api/settings/pots/deployments/${DEPLOYMENT_ID}" \
    -H "api_key: ${SHADOWTRAP_API_KEY}" -H 'Content-Type: application/json' \
    -d "{\"ttl_minutes\":1}" >/dev/null

sleep 90

# After rebuild, the new pot at the same deployment slot must not
# have the marker; we check the new pot's IP via API.
new_ip=$(curl -sS "${SHADOWTRAP_API}/api/info/pots" \
    -H "api_key: ${SHADOWTRAP_API_KEY}" \
    | jq -r ".pots[] | select(.deployment==\"${DEPLOYMENT_ID}\") | .ip" | head -n1)

if [[ -z "$new_ip" ]]; then
    echo "PASS=false (no replacement pot found)"
    exit 1
fi

still_present=$(sshpass -p "$POT_PASS" ssh -o StrictHostKeyChecking=no \
    "$POT_USER@$new_ip" 'crontab -l 2>/dev/null | grep -c a6-marker' || echo 0)
if [[ "$still_present" == 0 ]]; then
    echo "PASS=true"
else
    echo "PASS=false"
fi
