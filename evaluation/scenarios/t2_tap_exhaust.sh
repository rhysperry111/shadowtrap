#!/usr/bin/env bash
# T2.4 — Tap-device exhaustion recovery.
#
# Pre-allocates host taps vnet0..vnet1023, triggers a deployment so
# the next provision collides on tap creation, captures the
# scheduler's retry path (after the next reaper tick frees a tap),
# and cleans up.

set -euo pipefail

EVIDENCE="${EVIDENCE_DIR:-$(dirname "$0")/../evidence}"
mkdir -p "$EVIDENCE"
LOG="$EVIDENCE/scheduler.log"
: > "$LOG"

# Gate the test so we don't accidentally trash a real host network.
if [[ "${ALLOW_TAP_EXHAUST:-no}" != "yes" ]]; then
    echo "[skip] T2.4 requires ALLOW_TAP_EXHAUST=yes" | tee -a "$LOG"
    exit 0
fi

echo "[T2.4] pre-allocating taps vnet0..vnet1023" >> "$LOG"
for n in $(seq 0 1023); do
    sudo ip tuntap add dev vnet$n mode tap 2>/dev/null || true
done

# Create a fresh deployment with one replica; observe failure → retry.
dep="t2-tap-exhaust-$(date +%s)"
curl -sS -X POST "${SHADOWTRAP_API}/api/settings/pots/deployments" \
    -H "api_key: $SHADOWTRAP_API_KEY" \
    -H 'Content-Type: application/json' \
    -d "{\"id\":\"$dep\",\"active\":true,\"count\":1,\"image\":[{\"id\":\"$EVAL_IMAGE_ID\"}],\"network\":[{\"id\":\"$EVAL_NETWORK_ID\"}],\"ipam\":\"sweep\",\"ttl_minutes\":1}" >/dev/null

# Capture controller logs for the next 90 s.
journalctl --no-pager -u shadowtrap-controller --since "1 minute ago" -f &
JPID=$!
sleep 90
kill "$JPID" 2>/dev/null || true

journalctl --no-pager -u shadowtrap-controller --since "2 minutes ago" \
    | grep -E '(provision|tap|reaper|HELLO|degraded)' >> "$LOG"

# Cleanup
echo "[T2.4] cleaning up taps" >> "$LOG"
for n in $(seq 0 1023); do
    sudo ip link delete vnet$n 2>/dev/null || true
done
curl -sS -X DELETE "${SHADOWTRAP_API}/api/settings/pots/deployments/$dep" \
    -H "api_key: $SHADOWTRAP_API_KEY" >/dev/null
echo "T2.4 ok → $LOG"
