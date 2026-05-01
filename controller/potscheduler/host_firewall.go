package potscheduler

// Host-level stateful firewall backstop.
//
// The libvirt nwfilter (libvirt.go) is the primary, per-NIC egress
// control. The bridge-family nftables table installed here is a
// defence-in-depth layer running in the kernel's bridge forward path —
// it catches frames the per-NIC filter might miss (configuration drift
// after libvirtd restarts, frames crafted via raw sockets in a
// compromised pot, exotic EtherTypes the nwfilter doesn't model).
//
// Every drop is counted and logged with a "shadowtrap-drop:" prefix so
// the DropWatcher can map the source MAC back to a pot and trigger an
// immediate rebuild.
//
// Bootstrap installs this table before the controller serves any HTTP
// request. If it fails, fail-closed: the controller exits.

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// PotMACOUI is the 3-byte MAC prefix every pot NIC carries (encoded
// 02:73:74). RandomMAC seeds it; the nftables ruleset matches on it.
const PotMACOUI = "02:73:74"

// hostFirewallTable names the bridge-family nftables table this package
// owns. Anything in this table belongs to ShadowTrap and is rewritten
// from in-binary state on every Bootstrap.
const hostFirewallTable = "shadowtrap"

// hostFirewallRuleset is what gets installed at bootstrap.
//
//   - Frames whose source MAC carries the ShadowTrap OUI go through
//     pot_egress. Frames from other hosts on the bridge are ignored.
//   - ARP from a pot is allowed at L2 (the libvirt no-arp-spoofing
//     filter still enforces MAC/IP binding inside ARP frames).
//   - TCP/UDP replies on flows conntrack already knows about — i.e.
//     inbound probe traffic the operator wants the attacker to see —
//     are accepted.
//   - Everything else from a pot is logged with "shadowtrap-drop:",
//     counted, and dropped.
const hostFirewallRuleset = `table bridge shadowtrap {
    counter pot_egress_drops {
        comment "ShadowTrap: pot-initiated frames blocked at host bridge"
    }

    chain pot_filter {
        type filter hook forward priority filter; policy accept;

        # Match frames from any pot MAC (OUI 02:73:74). Frames from
        # legitimate hosts on the bridge — including the upstream
        # NIC's own traffic — pass through without inspection.
        ether saddr and ff:ff:ff:00:00:00 == 02:73:74:00:00:00 jump pot_egress
    }

    chain pot_egress {
        # ARP is policed at L2 by libvirt's no-arp-spoofing filter.
        ether type arp accept

        # Replies on flows initiated from outside the pot — the probe
        # traffic the operator wants the attacker to see.
        ct state established,related accept

        # Everything else: new outbound flows, IPv6 of any kind,
        # raw-socket frames, exotic L2 protocols. The log line carries
        # the source MAC so DropWatcher can attribute the offence back
        # to a specific pot.
        log prefix "shadowtrap-drop: " level warn counter name pot_egress_drops drop
    }
}
`

// VerifyHostFirewallPrereqs checks that nft is available and tries to
// load the kernel modules we depend on. modprobe is best-effort —
// modules may already be built in or auto-loaded by nft. A missing nft
// binary, however, is fatal.
//
// Conntrack support inside the bridge family — what makes the
// `ct state` clauses meaningful — is verified indirectly: nft refuses
// the ruleset if nft_ct isn't loaded for the bridge family, and
// Bootstrap surfaces that as a fail-closed exit.
func VerifyHostFirewallPrereqs() error {
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft binary not found in PATH; install the 'nftables' package")
	}
	for _, mod := range []string{"br_netfilter", "nf_conntrack", "nf_conntrack_bridge"} {
		_ = exec.Command("modprobe", mod).Run()
	}
	return nil
}

// EnsureHostFirewall (re-)installs the bridge-family nftables table.
// We tear the table down first so the install is idempotent — a
// controller upgrade carrying a new ruleset doesn't leave stale rules
// behind.
func EnsureHostFirewall() error {
	_ = exec.Command("nft", "delete", "table", "bridge", hostFirewallTable).Run()

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(hostFirewallRuleset)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install host firewall: %w: %s",
			err, strings.TrimSpace(string(out)))
	}
	return nil
}
