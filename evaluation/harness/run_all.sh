#!/usr/bin/env bash
# Run T1 -> T2 -> T3 -> T4 in sequence and roll the per-phase JSON
# files into evidence/results.json. Use --only to run just one phase.

set -euo pipefail

cd "$(dirname "$0")/.."

EVIDENCE="${EVIDENCE_DIR:-$(pwd)/evidence}"
RUNS="${RUNS:-10}"
ONLY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --only)
            ONLY="$2"
            shift 2
            ;;
        --runs)
            RUNS="$2"
            shift 2
            ;;
        -h|--help)
            cat <<EOF
Usage: run_all.sh [--only PHASE] [--runs N]
  --only t1.lab | t2.provisioning | t3.detection | t4.containment
  --runs N    runs per scenario (default 10)
EOF
            exit 0
            ;;
        *)
            echo "unknown flag: $1" >&2
            exit 2
            ;;
    esac
done

mkdir -p "$EVIDENCE"
export EVIDENCE_DIR="$EVIDENCE"

run_phase() {
    local phase="$1" cmd="$2"
    if [[ -n "$ONLY" && "$ONLY" != "$phase" ]]; then
        return 0
    fi
    echo
    echo "=== $phase ==="
    eval "$cmd"
}

run_phase t1.lab          "./lab/setup.sh"

run_phase t2.provisioning "./harness/t2_boot.py --runs 12 \
                           && ./scenarios/t2_sweep.sh \
                           && ./scenarios/t2_ipam.sh \
                           && ./scenarios/t2_tap_exhaust.sh"

run_phase t3.detection    "./harness/t3_detection.py --runs $RUNS"

run_phase t4.containment  "./harness/t4_containment.py"

./harness/finalise.py "$EVIDENCE"

echo
echo "All done -> $EVIDENCE/results.json"
