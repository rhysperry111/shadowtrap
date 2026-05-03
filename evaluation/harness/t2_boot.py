#!/usr/bin/env python3
"""
T2.1 — Boot and provisioning latency.

Triggers N pot provisionings via the controller API and times each one
by polling the API:

  appearance_s — deployment created -> pot row visible in /api/info/pots
  healthy_s    — appearance -> status flips to "healthy"
                 (i.e. the agent has heartbeated at least once)
  total_s      — deployment created -> healthy

The controller doesn't persist hello/heartbeat events to the database
(they're protocol messages, handled in-memory by potmgr/conn.go), so
polling the API is the only way to time them from outside.

Outputs:
  evidence/boot-latency.csv         (appearance -> healthy)
  evidence/provisioning-latency.csv (creation  -> healthy)
  evidence/t2_boot.summary.json     (p50, p95, n)
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

EVIDENCE = Path(os.environ.get("EVIDENCE_DIR", Path(__file__).parent.parent / "evidence"))
EVIDENCE.mkdir(parents=True, exist_ok=True)

API = os.environ.get("SHADOWTRAP_API", "http://127.0.0.1:8080")
KEY = os.environ["SHADOWTRAP_API_KEY"]

DEPLOYMENT_ID_PREFIX = "t2-boot"
TARGET_NETWORK = os.environ.get("EVAL_NETWORK_ID", "eval-net")
TARGET_IMAGE = os.environ.get("EVAL_IMAGE_ID", "ubuntu-24")

POLL_S = 1.0
TIMEOUT_S = 600


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--runs", type=int, default=42)
    return p.parse_args()


def curl_json(method: str, path: str, payload: dict | None = None) -> dict:
    cmd = [
        "curl", "-sS", "-X", method,
        "-H", f"api_key: {KEY}",
        "-H", "Content-Type: application/json",
        f"{API}{path}",
    ]
    if payload is not None:
        cmd += ["-d", json.dumps(payload)]

    out = subprocess.check_output(cmd)
    if not out:
        return {}

    try:
        return json.loads(out)
    except json.JSONDecodeError:
        print(f"[err] non-JSON response from {method} {path}: {out!r}", file=sys.stderr)
        return {}


def make_deployment(name: str, replicas: int) -> dict:
    body = curl_json("POST", "/api/settings/pots/deployments", {
        "id": name,
        "active": True,
        "count": replicas,
        "image": [{"id": TARGET_IMAGE}],
        "network": [{"id": TARGET_NETWORK}],
        "ipam": "sweep",
        "ttl_minutes": 60,
    })
    if "id" not in body:
        raise SystemExit(f"deployment creation failed: {body!r}")
    return body


def list_pots(deployment: str) -> list[dict]:
    pots = curl_json("GET", "/api/info/pots").get("pots", [])
    return [p for p in pots if p.get("deployment") == deployment]


def percentile(xs: list[float], pct: float) -> float:
    if not xs:
        return float("nan")
    xs = sorted(xs)
    k = int(round((pct / 100.0) * (len(xs) - 1)))
    return xs[k]


def median(xs: list[float]) -> float:
    return statistics.median(xs) if xs else float("nan")


def write_csv(path: Path, rows: list[dict], cols: list[str]) -> None:
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    args = parse_args()

    name = f"{DEPLOYMENT_ID_PREFIX}-{int(time.time())}"
    print(f"creating deployment {name} with {args.runs} replicas", file=sys.stderr)

    deploy_t = time.time()
    make_deployment(name, args.runs)

    appearance: dict[str, float] = {}   # pot_id -> first time seen
    healthy_t: dict[str, float] = {}    # pot_id -> first time healthy
    last_status: dict[str, str] = {}

    deadline = time.time() + TIMEOUT_S
    last_print = 0.0

    while time.time() < deadline:
        pots = list_pots(name)
        now = time.time()

        for p in pots:
            pid = p["id"]
            appearance.setdefault(pid, now)
            if p.get("status") == "healthy" and pid not in healthy_t:
                healthy_t[pid] = now
            last_status[pid] = p.get("status", "?")

        if now - last_print >= 5:
            statuses = {s: sum(1 for v in last_status.values() if v == s) for s in set(last_status.values())}
            print(
                f"  t={now - deploy_t:5.1f}s  "
                f"seen={len(appearance):>3}/{args.runs}  "
                f"healthy={len(healthy_t):>3}/{args.runs}  "
                f"statuses={statuses}",
                file=sys.stderr,
            )
            last_print = now

        if len(healthy_t) >= args.runs:
            break
        time.sleep(POLL_S)

    if not healthy_t:
        print(
            "[err] no pots reached 'healthy' within the timeout. Check the "
            "controller logs (journalctl -u shadowtrap-controller, or the "
            "foreground stdout): the most common causes are wrong "
            "EVAL_IMAGE_ID, wrong EVAL_NETWORK_ID, the agent not starting "
            "in the pot image, or a virtio-serial path mismatch.",
            file=sys.stderr,
        )

    boot_rows: list[dict] = []
    prov_rows: list[dict] = []
    for pid, h_t in sorted(healthy_t.items()):
        a_t = appearance.get(pid, h_t)
        boot_rows.append({
            "pot_id": pid,
            "appeared_at_unix": f"{a_t:.3f}",
            "healthy_at_unix": f"{h_t:.3f}",
            "delta_s": f"{h_t - a_t:.3f}",
        })
        prov_rows.append({
            "pot_id": pid,
            "deployment_created_at_unix": f"{deploy_t:.3f}",
            "healthy_at_unix": f"{h_t:.3f}",
            "delta_s": f"{h_t - deploy_t:.3f}",
        })

    write_csv(
        EVIDENCE / "boot-latency.csv",
        boot_rows,
        ["pot_id", "appeared_at_unix", "healthy_at_unix", "delta_s"],
    )
    write_csv(
        EVIDENCE / "provisioning-latency.csv",
        prov_rows,
        ["pot_id", "deployment_created_at_unix", "healthy_at_unix", "delta_s"],
    )

    boot_deltas = [float(r["delta_s"]) for r in boot_rows]
    prov_deltas = [float(r["delta_s"]) for r in prov_rows]
    summary = {
        "n_pots_seen":    len(appearance),
        "n_pots_healthy": len(healthy_t),
        "n_pots_target":  args.runs,
        "boot_p50_s":     median(boot_deltas),
        "boot_p95_s":     percentile(boot_deltas, 95),
        "prov_p50_s":     median(prov_deltas),
        "prov_p95_s":     percentile(prov_deltas, 95),
    }

    (EVIDENCE / "t2_boot.summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))

    return 0 if healthy_t else 1


if __name__ == "__main__":
    sys.exit(main())
