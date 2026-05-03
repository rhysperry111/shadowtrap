# ShadowTrap evaluation harness

This directory is the test harness for the dissertation's empirical
chapters (`§4.1`–`§4.4`) and the evidence appendix (`Appendix E`).
It contains five self-contained tests, an orchestrator that runs all
of them, and a JSON result-handback template you fill in (or the
orchestrator fills in for you) and send back so the dissertation's
`#dummy[]` blocks can be replaced with real numbers.

## At a glance

| Test | Covers | Runtime | Outputs |
| --- | --- | --- | --- |
| T1 — Lab setup & inventory | §4.1 host spec, binary sizes | ~10 min | `evidence/lab.json` |
| T2 — Provisioning latency & IPAM | §4.1.1, §4.1.2, E.1–E.5 | ~30 min | `evidence/boot-latency.csv`, `evidence/provisioning-latency.csv`, `evidence/sweep-run.log`, `evidence/ipam-compare.tsv`, `evidence/scheduler.log` |
| T3 — Detection effectiveness | §4.2, E.6, E.10 | ~2 h | `evidence/detection.csv`, `evidence/detection-summary.json`, `evidence/web-exploit-runs.log` |
| T4 — Containment integrity | §4.3, E.7–E.9 | ~1 h | `evidence/containment.json`, `evidence/nftables-counters.txt`, `evidence/cred-replay.log`, `evidence/watchdog-miss.log` |
| T5 — Background-traffic FPR | §4.2 0.16 FPR figure | runs alongside T3 | folded into `detection-summary.json` |

Total wall-clock budget: roughly 3.5 hours of unattended time after a
half-day of lab setup.

## Lab prerequisites

You need the following infrastructure before running anything:

- **Controller host (CH).** Linux 5.15+, KVM, libvirt 9.0+, PostgreSQL
  14+, nftables, Go 1.22+. Build the controller and agent per the
  project README. Capture `lscpu`, `free -h`, and the binary sizes
  for T1.
- **Pot base image.** An Ubuntu 24.04 cloud image with sshd,
  apache2, vsftpd, samba, postgres, mysql-server, xrdp installed and
  configured to log auth events; the agent installed as a systemd
  unit reading `/dev/vport0p0`. The image-build script is at
  `lab/build-pot-image.sh`.
- **Evaluation network.** A bridged /24 segment isolated from the
  Internet (the laboratory must be air-gapped — see the Ethical
  Issues Statement). Three "production" hosts on this segment for
  the lateral-movement and IPAM tests: a Linux jumphost on
  `10.10.42.10`, a Windows file server on `10.10.42.11`, an Ubuntu
  monitoring host on `10.10.42.12`.
- **Attacker VM (AV).** Kali Linux or equivalent with `nmap`,
  `hydra`, `metasploit-framework`, `curl`, and `tcpdump` installed.
  On the same evaluation segment.
- **Optional IPAM backends.** A phpIPAM 1.7 instance and a NetBox
  4.0 instance for T2.3, populated with the evaluation /24's
  occupancy data. If you skip these, T2.3 reports `skipped` and the
  dissertation will note phpIPAM/NetBox tests as absent.

The full topology is documented in [lab/topology.md](lab/topology.md).

## How to run

From the controller host, with the `shadowtrap-controller` running:

```sh
# One-time
$ cd shadowtrap/evaluation
$ ./lab/setup.sh                           # records lab inventory → evidence/lab.json

# Each test can be run independently or all at once
$ ./harness/run_all.sh                     # ~3.5 h, populates evidence/
```

`run_all.sh` runs T1 → T2 → T3 → T4 in order, with progress on
stdout. Each scenario in T3/T4 is run ten times by default; override
with `RUNS=5 ./harness/run_all.sh` to halve runtime.

If a single test fails, re-run only that one:

```sh
$ ./harness/run_all.sh --only t3.detection
$ ./harness/run_all.sh --only t4.containment
```

## Per-test guides

### T1 — Lab setup & inventory

`./lab/setup.sh` records:

- CPU, memory, kernel version (`/proc/cpuinfo`, `/proc/meminfo`,
  `uname -a`).
- Binary sizes (`stat -c '%s'` on `shadowtrap-controller`,
  `shadowtrap-agent`).
- libvirt and PostgreSQL versions.
- nftables ruleset hash.

Output: `evidence/lab.json`. Read by `harness/correlate.py` when it
populates the abstract and §4.1 lab paragraph.

### T2 — Provisioning latency & IPAM

Three sub-tests:

- **T2.1 Boot latency** — `harness/t2_boot.py`. Drives 42 pot
  provisionings via the controller API, records (deployment
  insert) → (`virsh start`) → (first `HELLO`) → (first
  `HEARTBEAT`) deltas by joining the events table with libvirt's
  domain-event log. Outputs `evidence/boot-latency.csv` and
  `evidence/provisioning-latency.csv`. Computes p50/p95.
- **T2.2 Sweep allocator accuracy** — `scenarios/t2_sweep.sh`. Runs
  the sweep allocator against the evaluation /24 with three known
  occupants. Records the allocator's reported free count vs the
  ground-truth list (the file `lab/ground-truth.txt`). Logs every
  probe to `evidence/sweep-run.log`.
- **T2.3 IPAM agreement** — `scenarios/t2_ipam.sh`. For each of
  phpIPAM and NetBox, performs 20 deployments with that backend
  selected and records the IP ShadowTrap chose vs the IPAM's "first
  free" record. Output: `evidence/ipam-compare.tsv`. If a backend
  is unreachable the row is omitted and the test reports a partial
  result.
- **T2.4 Tap-exhaustion recovery** — `scenarios/t2_tap_exhaust.sh`.
  Pre-allocates host taps `vnet0`–`vnet1023` with `ip tuntap add`,
  then triggers a deployment so the next provision hits the
  collision. Captures the scheduler's retry path to
  `evidence/scheduler.log`. Cleans up afterwards.

### T3 — Detection effectiveness

Six attack scenarios, each run `RUNS` times (default 10):

- **S1 TCP sweep** — `scenarios/s1_tcp_sweep.sh`: `nmap -sT -p-`
  across the /24. Each pot probed should emit at least one
  `connection` event from sshd or apache2.
- **S2 SSH credential stuffing** — `scenarios/s2_ssh_credstuff.sh`:
  `hydra -L users.txt -P passwords.txt ssh://<pot-ip>`. Each auth
  attempt should produce an `auth` event with `result=fail` /
  `result=invalid_user`.
- **S3 Web exploitation** — `scenarios/s3_web_exploit.sh`: a
  pre-recorded set of 50 malformed POST/GET requests against
  apache2 (path-traversal, command-injection in CGI, SQLi). Each
  should produce an HTTP `connection` event with status 4xx/5xx.
- **S4 Persistence attempt** — `scenarios/s4_persistence.sh`: after
  authenticating to the pot with the per-pot credentials extracted
  from the `events` table (`KindAuth` `result=success`), install a
  cron entry and an SSH key. Both should emit auth/command events
  and the cron must be discarded on the next TTL reap.
- **S5 Lateral movement** — `scenarios/s5_lateral.sh`: from a
  compromised pot, attempt SSH to a peer pot and SMB to the
  "production" file server. Both should be dropped and emit
  `containment / egress_blocked` events from the drop watcher.
- **S6 Egress attempt** — `scenarios/s6_egress.sh`: from a
  compromised pot, attempt outbound TCP to a public IP, outbound
  DNS, and ICMP tunnel. All three should drop and emit
  `egress_blocked`.

The harness `harness/t3_detection.py` runs each scenario, records
attacker timestamps for every discrete action, then queries the
events table (`evidence/events.sql`) to find the matching event,
computes time-to-alert as `event.time - action.time`. Outputs
`evidence/detection.csv` (one row per action) and
`evidence/detection-summary.json` (aggregated per scenario:
actions, detected, percent, p50/p95 t-to-alert).

T5 background traffic runs concurrently: every minute,
`scenarios/t5_background.sh` issues a benign monitoring probe (ping
+ TCP open-and-close on port 22 + HTTP HEAD) from each "production"
host. Background-traffic events are tagged `source=monitoring` and
counted as false positives if they are flagged by the watchdog or
drop watcher. The FPR is reported in `detection-summary.json`.

### T4 — Containment integrity

Nine attack scenarios, each run once with both pre- and post-counter
samples:

- A1 Outbound TCP to a public IP from a compromised pot.
- A2 Outbound DNS to attacker resolver.
- A3 ICMP tunnel to attacker host (paired with sustained inbound
  probe traffic to test the watchdog miss case described in
  Appendix E.8).
- A4 Lateral SSH to peer pot.
- A5 Lateral SMB to production host.
- A6 Cron persistence within pot lifetime; verify presence; wait
  for TTL; verify absence.
- A7 SSH key implant within pot lifetime; same shape.
- A8 Credential replay against peer pot.
- A9 Credential replay against production host.

`harness/t4_containment.py` orchestrates each. Before and after
every attack it captures `nft list table bridge shadowtrap`
(specifically the `pot_egress_drops` counter) and dumps it to
`evidence/nftables-counters.txt`. It queries the events table for
each scenario's expected event and records pass/fail per scenario
in `evidence/containment.json`. Credential-replay logs land in
`evidence/cred-replay.log`. The ICMP-tunnel watchdog miss is
documented in `evidence/watchdog-miss.log` from the watchdog
sample loop's per-tick rxΔ/txΔ records.