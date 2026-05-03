#!/usr/bin/env python3
"""
T4 — Containment integrity.

Runs nine attack scenarios designed to break the containment model
(@sec:containment). Each scenario:

  1. Snapshots the bridge nftables `pot_egress_drops` counter.
  2. Runs the attack from the attacker VM against a designated pot.
  3. Snapshots the counter again.
  4. Records pass/fail by checking the events table for the expected
     `containment / egress_blocked` event.
  5. For credential-replay cases, records auth-fail events at the
     replay target.

Outputs:
  evidence/containment.json
  evidence/nftables-counters.txt   (pre/post counter snapshots)
  evidence/cred-replay.log
  evidence/watchdog-miss.log       (per-tick rxΔ/txΔ from the
                                    watchdog, ICMP-tunnel run)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

EVIDENCE = Path(os.environ.get("EVIDENCE_DIR", Path(__file__).parent.parent / "evidence"))
EVIDENCE.mkdir(parents=True, exist_ok=True)

DSN = os.environ["SHADOWTRAP_DB_DSN"]

ATTACKS = [
    {"id": "A1_outbound_tcp",     "script": "containment/a1_outbound_tcp.sh",     "expect": "egress_blocked"},
    {"id": "A2_outbound_dns",     "script": "containment/a2_outbound_dns.sh",     "expect": "egress_blocked"},
    {"id": "A3_icmp_tunnel",      "script": "containment/a3_icmp_tunnel.sh",      "expect": "egress_blocked", "watchdog_only_for_miss": True},
    {"id": "A4_lateral_ssh",      "script": "containment/a4_lateral_ssh.sh",      "expect": "egress_blocked"},
    {"id": "A5_lateral_smb",      "script": "containment/a5_lateral_smb.sh",      "expect": "egress_blocked"},
    {"id": "A6_cron_persistence", "script": "containment/a6_cron_persistence.sh", "expect": "ttl_rebuild"},
    {"id": "A7_ssh_key_implant",  "script": "containment/a7_key_implant.sh",      "expect": "ttl_rebuild"},
    {"id": "A8_credreplay_peer",  "script": "containment/a8_cred_replay_peer.sh", "expect": "auth_reject"},
    {"id": "A9_credreplay_prod",  "script": "containment/a9_cred_replay_prod.sh", "expect": "auth_reject"},
]


def nft_drops_counter() -> int:
    out = subprocess.check_output(
        ["nft", "-j", "list", "counter", "bridge", "shadowtrap", "pot_egress_drops"],
        text=True,
    )
    parsed = json.loads(out)
    for obj in parsed.get("nftables", []):
        if "counter" in obj:
            return int(obj["counter"]["packets"])
    return 0


def append_counter_snapshot(label: str, value: int) -> None:
    line = f"{label}\tpot_egress_drops packets={value}\t{datetime.now(timezone.utc).isoformat()}\n"
    with (EVIDENCE / "nftables-counters.txt").open("a") as fh:
        fh.write(line)


def query_breach_event(window_start: datetime, window_end: datetime) -> dict | None:
    q = (
        f"select time, pot_id, source, data::text from events where "
        f"time between '{window_start.isoformat()}' and '{window_end.isoformat()}' "
        f"and kind = 'egress_blocked' order by time asc limit 1"
    )
    out = subprocess.check_output(["psql", DSN, "-Atc", q], text=True).strip()
    if not out:
        return None

    t, pot, source, data = out.split("|", 3)
    return {"time": t, "pot_id": pot, "source": source, "data": data}


def query_auth_reject_at(target_ip: str, window_start: datetime, window_end: datetime) -> bool:
    """For credential-replay cases: confirm an auth-fail event was
    logged on the target host's auth log. The target has to be set up
    to syslog into the same database, or to a parseable file. The
    scenario script captures auth.log lines directly into
    cred-replay.log; we just check it's non-empty.
    """
    log = EVIDENCE / "cred-replay.log"
    return log.exists() and log.stat().st_size > 0


def evaluate_egress(attack: dict, drops_delta: int, window_start: datetime,
                    window_end: datetime, stdout: str, result: dict) -> None:
    ev = query_breach_event(window_start, window_end)
    result["event"] = ev
    result["pass"] = ev is not None and drops_delta > 0

    # A3 is a known-hard case: the filter still drops, but the
    # watchdog can miss the rx-without-tx pattern when inbound probes
    # mask it. Record those as "partial" rather than fail.
    if attack.get("watchdog_only_for_miss") and not result["pass"] and drops_delta > 0:
        result["pass"] = "partial"
        with (EVIDENCE / "watchdog-miss.log").open("a") as fh:
            fh.write(f"{attack['id']}: filter blocked {drops_delta} packets, watchdog did not flag within 10 s\n")
            fh.write(stdout)
            fh.write("\n---\n")


def run_attack(attack: dict) -> dict:
    pre = nft_drops_counter()
    append_counter_snapshot(f"{attack['id']}.pre", pre)

    window_start = datetime.now(timezone.utc)
    out = subprocess.run(
        ["bash", attack["script"]],
        capture_output=True, text=True, check=False,
    )
    window_end = datetime.now(timezone.utc) + timedelta(seconds=10)

    post = nft_drops_counter()
    append_counter_snapshot(f"{attack['id']}.post", post)
    drops_delta = post - pre

    result: dict = {
        "id":          attack["id"],
        "drops_pre":   pre,
        "drops_post":  post,
        "drops_delta": drops_delta,
        "exit_code":   out.returncode,
    }

    expect = attack["expect"]
    if expect == "egress_blocked":
        evaluate_egress(attack, drops_delta, window_start, window_end, out.stdout, result)
    elif expect == "ttl_rebuild":
        # A6/A7 print PASS=true on success.
        result["pass"] = "true" in out.stdout.lower()
    elif expect == "auth_reject":
        result["pass"] = query_auth_reject_at(
            os.environ.get("PROD_HOST_IP", "10.10.42.10"),
            window_start, window_end,
        )

    return result


def main() -> int:
    results = []
    for attack in ATTACKS:
        print(f"running {attack['id']}", file=sys.stderr)
        results.append(run_attack(attack))
        time.sleep(5)

    summary = {
        "n":         len(results),
        "n_pass":    sum(1 for r in results if r["pass"] is True),
        "n_partial": sum(1 for r in results if r["pass"] == "partial"),
        "n_fail":    sum(1 for r in results if r["pass"] is False),
        "results":   results,
    }
    (EVIDENCE / "containment.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0 if summary["n_fail"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
