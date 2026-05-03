#!/usr/bin/env python3
"""
T3 — Detection effectiveness.

Runs each of six attack scenarios `--runs` times, recording per-action
attacker timestamps, then queries the events table to compute, per
scenario:

  - actions issued
  - actions detected (an event matched within 30 s and from the
    correct source IP)
  - median time-to-alert
  - p95 time-to-alert

T5 background traffic runs concurrently from the production hosts so
we can quantify false positives.

Outputs:
  evidence/detection.csv          (one row per action)
  evidence/detection-summary.json (per-scenario aggregate + FPR)
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

EVIDENCE = Path(os.environ.get("EVIDENCE_DIR", Path(__file__).parent.parent / "evidence"))
EVIDENCE.mkdir(parents=True, exist_ok=True)

DSN = os.environ["SHADOWTRAP_DB_DSN"]

SCENARIOS = [
    ("S1_tcp_sweep",     "scenarios/s1_tcp_sweep.sh"),
    ("S2_ssh_credstuff", "scenarios/s2_ssh_credstuff.sh"),
    ("S3_web_exploit",   "scenarios/s3_web_exploit.sh"),
    ("S4_persistence",   "scenarios/s4_persistence.sh"),
    ("S5_lateral",       "scenarios/s5_lateral.sh"),
    ("S6_egress",        "scenarios/s6_egress.sh"),
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--runs", type=int, default=10)
    return p.parse_args()


def run_scenario(name: str, script: str, run_idx: int) -> list[dict]:
    """Run the scenario script and parse the actions log it writes to
    stdout in JSONL form: one JSON object per attacker action with
    keys {time, source, kind, target, expected_pot_id (optional)}.

    The scripts emit these themselves — a line like
        echo '{"time":"...","kind":"auth","source":"...","target":"..."}'
    is enough.
    """
    out = subprocess.run(
        ["bash", script, "--runs-tag", f"{name}-{run_idx}"],
        capture_output=True, text=True, check=False,
    )
    if out.returncode != 0:
        print(f"[warn] {name} run {run_idx} exit={out.returncode}", file=sys.stderr)

    actions = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            actions.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return actions


def query_events_for_action(action: dict) -> dict | None:
    """Find the earliest matching event within 30 s of the action."""
    src = action["source"]
    target = action.get("target")
    base_t = parse_iso(action["time"])
    horizon = (base_t + timedelta(seconds=30)).isoformat()

    where = [
        f"time >= '{action['time']}'",
        f"time <= '{horizon}'",
        f"source LIKE '{src}%'",
    ]
    if target:
        where.append(f"pot_id IN (SELECT id FROM pots WHERE ip = '{target}')")

    q = (
        "select time, pot_id, service, kind, source, data::text from events where "
        + " and ".join(where)
        + " order by time asc limit 1"
    )

    out = subprocess.check_output(["psql", DSN, "-Atc", q], text=True).strip()
    if not out:
        return None

    parts = out.split("|", 5)
    return {
        "time":    parts[0],
        "pot_id":  parts[1],
        "service": parts[2],
        "kind":    parts[3],
        "source":  parts[4],
        "data":    parts[5],
    }


def parse_iso(s: str) -> datetime:
    s = s.replace("Z", "+00:00")
    return datetime.fromisoformat(s).astimezone(timezone.utc)


def percentile(xs: list[float], pct: float) -> float:
    if not xs:
        return float("nan")
    xs = sorted(xs)
    k = int(round((pct / 100.0) * (len(xs) - 1)))
    return xs[k]


def write_csv(path: Path, rows: list[dict], cols: list[str]) -> None:
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def collect_rows(args: argparse.Namespace) -> list[dict]:
    rows: list[dict] = []
    for name, script in SCENARIOS:
        for run_idx in range(1, args.runs + 1):
            for action in run_scenario(name, script, run_idx):
                event = query_events_for_action(action)
                detected = event is not None

                delta = ""
                if detected:
                    delta_s = (parse_iso(event["time"]) - parse_iso(action["time"])).total_seconds()
                    delta = f"{delta_s:.3f}"

                rows.append({
                    "scenario":      name,
                    "run":           run_idx,
                    "action_time":   action["time"],
                    "action_kind":   action.get("kind", ""),
                    "action_source": action["source"],
                    "action_target": action.get("target", ""),
                    "detected":      detected,
                    "event_time":    event["time"] if detected else "",
                    "event_kind":    event["kind"] if detected else "",
                    "delta_s":       delta,
                })
    return rows


def summarise(rows: list[dict]) -> dict:
    summary: dict = {}
    for name, _ in SCENARIOS:
        scen_rows = [r for r in rows if r["scenario"] == name]
        deltas = [float(r["delta_s"]) for r in scen_rows if r["detected"]]

        summary[name] = {
            "actions":          len(scen_rows),
            "detected":         sum(1 for r in scen_rows if r["detected"]),
            "p50_t_to_alert_s": statistics.median(deltas) if deltas else None,
            "p95_t_to_alert_s": percentile(deltas, 95) if deltas else None,
        }
        if summary[name]["actions"]:
            summary[name]["detection_pct"] = round(
                100 * summary[name]["detected"] / summary[name]["actions"], 1
            )
    return summary


def measure_fpr(bg_started: datetime, bg_stopped: datetime) -> dict:
    bg_window_h = (bg_stopped - bg_started).total_seconds() / 3600.0

    fpr_q = (
        f"select count(*) from events where "
        f"time between '{bg_started.isoformat()}' and '{bg_stopped.isoformat()}' "
        f"and source LIKE '10.10.42.12%'"
    )
    fp_count = int(subprocess.check_output(["psql", DSN, "-Atc", fpr_q], text=True).strip() or 0)

    pots_q = "select count(*) from pots"
    n_pots = max(int(subprocess.check_output(["psql", DSN, "-Atc", pots_q], text=True).strip() or 1), 1)

    return {
        "background_window_h":     round(bg_window_h, 3),
        "false_positive_events":   fp_count,
        "pots_in_deployment":      n_pots,
        "events_per_pot_per_hour": round(fp_count / (n_pots * max(bg_window_h, 1e-9)), 3),
    }


def main() -> int:
    args = parse_args()

    bg = subprocess.Popen(
        ["bash", "scenarios/t5_background.sh"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    bg_started = datetime.now(timezone.utc)

    try:
        rows = collect_rows(args)
    finally:
        bg.terminate()
        bg.wait(timeout=10)
        bg_stopped = datetime.now(timezone.utc)

    write_csv(
        EVIDENCE / "detection.csv",
        rows,
        [
            "scenario", "run", "action_time", "action_kind", "action_source",
            "action_target", "detected", "event_time", "event_kind", "delta_s",
        ],
    )

    summary = summarise(rows)
    summary["_fpr"] = measure_fpr(bg_started, bg_stopped)

    (EVIDENCE / "detection-summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
