// Package ipam provides IP address allocation strategies for pots.
package ipam

import (
	"fmt"
	"net"
	"os/exec"
	"time"
)

// Allocator allocates and releases IPs within a subnet.
type Allocator interface {
	Allocate(subnet string) (ip string, err error)
	Release(ip string) error
}

// SweepAllocator finds free IPs by pinging each address. An IP is
// considered free when it doesn't reply within ~500 ms.
type SweepAllocator struct {
	reserved map[string]bool
}

func NewSweep() *SweepAllocator {
	return &SweepAllocator{reserved: make(map[string]bool)}
}

func (s *SweepAllocator) Allocate(subnet string) (string, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("ipam: parse subnet %q: %w", subnet, err)
	}

	for ip := cloneIP(ipNet.IP); ipNet.Contains(ip); incrementIP(ip) {
		candidate := ip.String()
		if isNetworkOrBroadcast(ip, ipNet) {
			continue
		}
		if s.reserved[candidate] {
			continue
		}
		if pingResponds(candidate) {
			continue
		}
		s.reserved[candidate] = true
		return candidate, nil
	}
	return "", fmt.Errorf("ipam: no free IP in %s", subnet)
}

func (s *SweepAllocator) Release(ip string) error {
	delete(s.reserved, ip)
	return nil
}

func pingResponds(ip string) bool {
	cmd := exec.Command("ping", "-c1", "-W1", ip)
	cmd.WaitDelay = 2 * time.Second
	return cmd.Run() == nil
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// isNetworkOrBroadcast reports whether ip is the all-zero-host or
// all-one-host address of the network.
func isNetworkOrBroadcast(ip net.IP, network *net.IPNet) bool {
	if ip.Equal(network.IP) {
		return true
	}
	broadcast := make(net.IP, len(network.IP))
	for i := range network.IP {
		broadcast[i] = network.IP[i] | ^network.Mask[i]
	}
	return ip.Equal(broadcast)
}
