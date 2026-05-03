#!/usr/bin/env bash
# T2.3 — phpIPAM / NetBox allocator agreement.
#
# For each of phpIPAM and NetBox, perform 20 deployments with that
# backend selected and record the IP ShadowTrap chose vs the IPAM's
# "first free" record.
#
# Skips the test if PHPIPAM_URL / NETBOX_URL are unset.

set -euo pipefail

EVIDENCE="${EVIDENCE_DIR:-$(dirname "$0")/../evidence}"
mkdir -p "$EVIDENCE"
TSV="$EVIDENCE/ipam-compare.tsv"
SUM="$EVIDENCE/t2_ipam.summary.json"

echo -e "deployment_id\tbackend\tshadowtrap_ip\tipam_first_free\tmatch" > "$TSV"

count_match=0
count_total=0
for backend in phpipam netbox; do
    case "$backend" in
        phpipam)
            url="${PHPIPAM_URL:-}"
            [[ -z "$url" ]] && { echo "[skip] phpIPAM not configured"; continue; }
            ;;
        netbox)
            url="${NETBOX_URL:-}"
            [[ -z "$url" ]] && { echo "[skip] NetBox not configured"; continue; }
            ;;
    esac

    for i in $(seq 1 20); do
        dep="t2-ipam-$backend-$(date +%s%N | head -c12)"
        # Create deployment with the chosen backend; record the IP.
        ip=$(curl -sS -X POST "${SHADOWTRAP_API}/api/settings/pots/deployments" \
            -H "api_key: $SHADOWTRAP_API_KEY" \
            -H 'Content-Type: application/json' \
            -d "{\"id\":\"$dep\",\"active\":true,\"count\":1,\"image\":[{\"id\":\"$EVAL_IMAGE_ID\"}],\"network\":[{\"id\":\"$EVAL_NETWORK_ID\"}],\"ipam\":\"$backend\"}" \
            | jq -r '.assigned_ip // empty')

        # Query the IPAM directly for what it would pick now.
        first_free=$(curl -sS "${url}/api/v1/first-free?subnet=${EVAL_SUBNET}" \
            -H "Authorization: $IPAM_TOKEN" | jq -r '.address // empty')

        match="no"; [[ "$ip" == "$first_free" ]] && match="yes"
        echo -e "${dep}\t${backend}\t${ip}\t${first_free}\t${match}" >> "$TSV"
        count_total=$((count_total + 1))
        [[ "$match" == "yes" ]] && count_match=$((count_match + 1))

        # Tear down the deployment to free the IP for the next iteration.
        curl -sS -X DELETE "${SHADOWTRAP_API}/api/settings/pots/deployments/$dep" \
            -H "api_key: $SHADOWTRAP_API_KEY" >/dev/null
    done
done

cat > "$SUM" <<EOF
{
  "total_deployments": $count_total,
  "ip_matches_first_free": $count_match,
  "agreement_pct": $(awk "BEGIN{printf \"%.1f\", $count_match * 100 / ($count_total > 0 ? $count_total : 1)}")
}
EOF

echo "T2.3 ok → $TSV"
