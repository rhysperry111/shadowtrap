#!/usr/bin/env python3
"""
Roll the per-phase JSON outputs into a single results.json that
matches the schema in evaluation/results.template.json.

Reads:
  evidence/lab.json
  evidence/t2_boot.summary.json
  evidence/detection-summary.json
  evidence/containment.json

Writes:
  evidence/results.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def load(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def main(evidence: str) -> int:
    ev = Path(evidence)

    lab = load(ev / "lab.json")
    boot = load(ev / "t2_boot.summary.json")
    det = load(ev / "detection-summary.json")
    cont = load(ev / "containment.json")

    fpr = det.pop("_fpr", {}) if det else {}

    out = {
        "schema_version": 1,
        "captured_at": lab.get("captured_at"),
        "lab": lab,
        "provisioning": {
            "n_lifecycles": boot.get("n_prov"),
            "boot_p50_s":   boot.get("boot_p50_s"),
            "boot_p95_s":   boot.get("boot_p95_s"),
            "prov_p50_s":   boot.get("prov_p50_s"),
            "prov_p95_s":   boot.get("prov_p95_s"),

            # Filled in by the t2 sweep / ipam scripts when they run.
            "sweep": load(ev / "t2_sweep.summary.json"),
            "ipam":  load(ev / "t2_ipam.summary.json"),

            "tap_exhaust_recovered": (ev / "scheduler.log").exists(),
        },
        "detection":   det,
        "fpr":         fpr,
        "containment": cont,
    }

    (ev / "results.json").write_text(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "evidence"))
