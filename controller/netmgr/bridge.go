package netmgr

// Linux bridge management for pot networks.
//
// Each ShadowTrap network sits on a Linux bridge we manage ourselves
// rather than libvirt's macvtap (`type='direct'` mode='bridge'). Macvtap
// is convenient — no host setup needed — but it has two well-known
// limitations for a deception platform:
//
//   1. It refuses to attach to a parent that is already bridged. Any
//      operator who has already moved their NIC into a Linux bridge
//      can't run pots on it without rearchitecting their host.
//   2. It blocks host-to-guest traffic on the same parent NIC. Talking
//      to the agent over virtio-serial sidesteps that for us, but
//      operators still want to ping or shell into a pot for debugging.
//
// A real bridge with one tap per pot avoids both. Bridge and VLAN setup
// goes through `ip link`, which needs CAP_NET_ADMIN — usually by running
// as root or:
//
//   # setcap cap_net_admin+ep /usr/local/bin/shadowtrap-controller

import (
	"fmt"
	"hash/fnv"
	"os/exec"
	"strings"
)

// BridgeName turns a network ID into a Linux bridge name.
//
// Linux caps interface names at 15 chars (IFNAMSIZ-1), so an arbitrary
// user-supplied ID isn't safe to use directly. Hashing to a fixed
// "stb<8 hex>" form keeps every name under the limit and deterministic.
func BridgeName(networkID string) string {
	return fmt.Sprintf("stb%08x", fnvHash(networkID))
}

// VLANIfaceName returns the VLAN sub-interface name. Same naming
// rationale as BridgeName.
func VLANIfaceName(networkID string) string {
	return fmt.Sprintf("stv%08x", fnvHash(networkID+":vlan"))
}

func fnvHash(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}

// EnsureBridge creates the bridge if it isn't there yet, and brings it
// up. Idempotent: safe to call on every pot provision.
func EnsureBridge(bridge string) error {
	if linkExists(bridge) {
		return ipLink("set", bridge, "up")
	}
	if err := ipLink("add", "name", bridge, "type", "bridge"); err != nil {
		return fmt.Errorf("create bridge %s: %w", bridge, err)
	}
	return ipLink("set", bridge, "up")
}

// EnsurePotNetwork makes sure the bridge for networkID exists and the
// parent NIC (or its VLAN sub-interface, when vlanID > 0) is enslaved
// to it. Returns the bridge name pots should attach to.
//
// Enslaving a parent NIC moves its layer-3 config onto the bridge. The
// operator is expected to have arranged things so this is safe — usually
// by running the controller on a host whose management IP lives on a
// different NIC from the pot-facing one.
//
// If parent is empty the bridge stands alone, which is useful for
// closed-lab tests where pots only ever talk to each other.
func EnsurePotNetwork(networkID, parent string, vlanID int32) (string, error) {
	bridge := BridgeName(networkID)
	if err := EnsureBridge(bridge); err != nil {
		return "", err
	}

	if parent == "" {
		return bridge, nil
	}

	slave := parent
	if vlanID > 0 {
		vlanIface := VLANIfaceName(networkID)
		if err := ensureVLANIface(parent, vlanIface, vlanID); err != nil {
			return "", err
		}
		slave = vlanIface
	}

	if err := ensureEnslaved(slave, bridge); err != nil {
		return "", err
	}
	return bridge, nil
}

// ensureVLANIface creates a `parent.vlanID` VLAN sub-interface if it's
// missing. Modern kernels auto-load the 8021q module on first add.
func ensureVLANIface(parent, name string, vlanID int32) error {
	if linkExists(name) {
		return ipLink("set", name, "up")
	}
	err := ipLink("add", "link", parent, "name", name,
		"type", "vlan", "id", fmt.Sprintf("%d", vlanID))
	if err != nil {
		return fmt.Errorf("create vlan %s on %s: %w", name, parent, err)
	}
	return ipLink("set", name, "up")
}

// ensureEnslaved makes child a slave of bridge and brings it up.
// Re-running this with the same bridge is a no-op.
func ensureEnslaved(child, bridge string) error {
	if err := ipLink("set", child, "master", bridge); err != nil {
		return fmt.Errorf("enslave %s -> %s: %w", child, bridge, err)
	}
	if err := ipLink("set", child, "up"); err != nil {
		return fmt.Errorf("bring up %s: %w", child, err)
	}
	return nil
}

// RemoveBridge tears down the bridge if it exists.
func RemoveBridge(bridge string) error {
	if !linkExists(bridge) {
		return nil
	}
	return ipLink("delete", bridge, "type", "bridge")
}

func linkExists(name string) bool {
	return exec.Command("ip", "link", "show", name).Run() == nil
}

func ipLink(args ...string) error {
	full := append([]string{"link"}, args...)
	out, err := exec.Command("ip", full...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip link %s: %s",
			strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}
