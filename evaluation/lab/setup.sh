#!/usr/bin/env bash
# T1 — Lab setup and inventory.
#
# Records the host's hardware, software versions, and binary sizes
# into evidence/lab.json so the dissertation's §4.1 paragraph and the
# Abstract findings block stay reproducible. Idempotent.

set -euo pipefail

EVIDENCE="${EVIDENCE_DIR:-$(dirname "$0")/../evidence}"
mkdir -p "$EVIDENCE"

CTRL_BIN="${SHADOWTRAP_CONTROLLER_BIN:-../controller/shadowtrap-controller}"
AGENT_BIN="${SHADOWTRAP_AGENT_BIN:-../agent/shadowtrap-agent}"

if [[ ! -x "$CTRL_BIN" ]]; then
    echo "controller binary not found at $CTRL_BIN; build it first" >&2
    exit 1
fi
if [[ ! -x "$AGENT_BIN" ]]; then
    echo "agent binary not found at $AGENT_BIN; build it first" >&2
    exit 1
fi

# Hardware.
cpu_model="$(awk -F: '/model name/{gsub(/^ +/,"",$2); print $2; exit}' /proc/cpuinfo)"
cpu_cores="$(nproc)"
mem_gib="$(awk '/MemTotal/ {printf "%.1f", $2/1024/1024}' /proc/meminfo)"

# OS.
kernel="$(uname -r)"
distro="$(. /etc/os-release; echo "$PRETTY_NAME")"

# Software versions.
libvirt_version="$(libvirtd --version 2>/dev/null | awk '{print $NF}' || echo unknown)"
qemu_version="$(qemu-system-x86_64 --version 2>/dev/null | head -n1 | awk '{print $4}' || echo unknown)"
postgres_version="$(psql --version 2>/dev/null | awk '{print $3}' || echo unknown)"
nft_version="$(nft --version 2>/dev/null | awk '{print $2}' || echo unknown)"
go_version="$(go version 2>/dev/null | awk '{print $3}' || echo unknown)"

# Binary sizes.
ctrl_size="$(stat -c '%s' "$CTRL_BIN")"
agent_size="$(stat -c '%s' "$AGENT_BIN")"
ctrl_mib=$(awk -v s="$ctrl_size" 'BEGIN{printf "%.1f", s/1024/1024}')
agent_mib=$(awk -v s="$agent_size" 'BEGIN{printf "%.1f", s/1024/1024}')

cat > "$EVIDENCE/lab.json" <<EOF
{
  "captured_at": "$(date --iso-8601=seconds)",
  "host": {
    "cpu_model": "$cpu_model",
    "cpu_cores": $cpu_cores,
    "memory_gib": $mem_gib,
    "kernel": "$kernel",
    "distro": "$distro"
  },
  "software": {
    "libvirt": "$libvirt_version",
    "qemu": "$qemu_version",
    "postgres": "$postgres_version",
    "nftables": "$nft_version",
    "go": "$go_version"
  },
  "binaries": {
    "controller_bytes": $ctrl_size,
    "agent_bytes": $agent_size,
    "controller_mib": $ctrl_mib,
    "agent_mib": $agent_mib
  }
}
EOF

echo "T1 ok -> $EVIDENCE/lab.json"
