#!/usr/bin/env bash
# T2.2 — Sweep allocator accuracy.
#
# Exercises the controller's `sweep` IPAM allocator against the
# evaluation /24 with a known set of occupants (lab/ground-truth.txt).
# Compares the allocator's choices against the ground truth, and
# logs every probe to evidence/sweep-run.log.

set -euo pipefail

EVIDENCE="${EVIDENCE_DIR:-$(dirname "$0")/../evidence}"
GROUND="${GROUND_TRUTH:-$(dirname "$0")/../lab/ground-truth.txt}"
NET="${EVAL_NETWORK:-10.10.42.0/24}"
LOG="$EVIDENCE/sweep-run.log"

mkdir -p "$EVIDENCE"
: > "$LOG"

# Run the standalone sweep tool (built from agent/ipam/sweep_main.go)
# to enumerate free addresses; the same allocator the controller uses.
go run ./../controller/cmd/sweep --subnet "$NET" --verbose 2>>"$LOG" \
    | tee "$EVIDENCE/sweep-result.txt"

# Compare against ground truth.
awk '!/^#/ && NF' "$GROUND" | sort > /tmp/.gt.$$.txt
sort "$EVIDENCE/sweep-result.txt" > /tmp/.swp.$$.txt
matched=$(comm -23 /tmp/.gt.$$.txt /tmp/.swp.$$.txt | wc -l)
total_occupied=$(wc -l < /tmp/.gt.$$.txt)
free_reported=$(wc -l < /tmp/.swp.$$.txt)

cat > "$EVIDENCE/t2_sweep.summary.json" <<EOF
{
  "subnet": "$NET",
  "occupied_ground_truth": $total_occupied,
  "free_reported_by_sweep": $free_reported,
  "ground_truth_misses": $matched
}
EOF

rm -f /tmp/.gt.$$.txt /tmp/.swp.$$.txt
echo "T2.2 ok → $EVIDENCE/t2_sweep.summary.json"
