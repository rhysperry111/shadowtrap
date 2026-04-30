// Package netmgr handles the network layer for pots: provisioning the
// libvirt-side bridges and VLANs, allocating IPs through pluggable IPAM
// backends, and discovering host interfaces.
package netmgr

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"shadowtrap/controller/netmgr/ipam"
)

type Manager struct {
	networks  NetworkClient
	imagesDir string
	runDir    string
}

func New(networks NetworkClient, imagesDir, runDir string) *Manager {
	return &Manager{networks: networks, imagesDir: imagesDir, runDir: runDir}
}

// AllocateIP picks a free IP from subnet using the named IPAM backend.
// opts is a single optional map of strategy-specific parameters
// (url/token/etc.).
func (m *Manager) AllocateIP(strategy, subnet string, opts ...map[string]string) (string, error) {
	var firstOpts map[string]string
	if len(opts) > 0 {
		firstOpts = opts[0]
	}

	allocator, err := m.newAllocator(strategy, firstOpts)
	if err != nil {
		return "", err
	}
	return allocator.Allocate(subnet)
}

func (m *Manager) newAllocator(strategy string, opts map[string]string) (ipam.Allocator, error) {
	switch strategy {
	case "sweep", "":
		return ipam.NewSweep(), nil
	case "phpipam":
		return ipam.NewPhpIPAM(opts["url"], opts["app_id"], opts["api_key"]), nil
	case "netbox":
		return ipam.NewNetBox(opts["url"], opts["token"]), nil
	default:
		return nil, fmt.Errorf("netmgr: unknown IPAM strategy %q", strategy)
	}
}

// ProvisionNetwork makes sure a Linux bridge exists for the network and
// the parent NIC (or its tagged sub-interface, for VLANs) is enslaved to
// it. Returns the bridge name the pot domain XML should attach to.
//
// We manage the bridge directly rather than using libvirt's macvtap so
// that pots can use `<interface type='bridge'>`. The reasons are in
// netmgr/bridge.go.
func (m *Manager) ProvisionNetwork(id, interfaceID, netType string, vlanID int32) (string, error) {
	vlan := int32(0)
	if netType == "vlan" {
		vlan = vlanID
	}
	return EnsurePotNetwork(id, interfaceID, vlan)
}

// DeprovisionNetwork removes the bridge for a network. Best-effort —
// any failure is reported but does not block deletion of the upstream
// record.
func (m *Manager) DeprovisionNetwork(id, netType string) error {
	return RemoveBridge(BridgeName(id))
}

func (m *Manager) BaseImagePath(imageID string) string {
	return filepath.Join(m.imagesDir, imageID+".qcow2")
}

func (m *Manager) SocketPath(domName string) string {
	return filepath.Join(m.runDir, "pots", domName, "serial.sock")
}

// virtualInterfacePrefixes are name prefixes ScanInterfaces hides:
// libvirt's own bridges, Docker, veths, and our own pot bridges. None
// are useful candidates for the operator to pick from.
var virtualInterfacePrefixes = []string{"virbr", "docker", "veth", "br-", "st-"}

// ScanInterfaces returns the host's physical NICs.
func (m *Manager) ScanInterfaces() ([]InterfaceInfo, error) {
	hostInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var physical []InterfaceInfo
	for _, iface := range hostInterfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if hasAnyPrefix(iface.Name, virtualInterfacePrefixes) {
			continue
		}
		isUp := iface.Flags&net.FlagUp != 0
		physical = append(physical, InterfaceInfo{
			ID:      iface.Name,
			Enabled: isUp,
			Link:    isUp,
		})
	}
	return physical, nil
}

func hasAnyPrefix(name string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

type InterfaceInfo struct {
	ID      string
	Enabled bool
	Link    bool
}
