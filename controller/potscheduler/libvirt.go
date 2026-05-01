package potscheduler

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"text/template"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// DomainClient is the slice of libvirt's domain API the scheduler and
// watchdog depend on.
type DomainClient interface {
	Define(xml string) error
	Start(name string) error
	Stop(name string) error    // graceful shutdown
	Destroy(name string) error // force off
	Undefine(name string) error
	Exists(name string) (bool, error)
	DefineNWFilter(xml string) error

	// InterfaceStats returns per-interface packet counters. device may
	// be the target NIC name (macvtap0, ...) or the MAC string — both
	// are accepted by modern libvirt. rxPackets are bytes the host has
	// received from the guest (i.e. guest-initiated traffic); tx is
	// the reverse.
	InterfaceStats(domName, device string) (rxPackets, txPackets int64, err error)
}

// LibvirtDomainClient is the production DomainClient.
type LibvirtDomainClient struct {
	l *golibvirt.Libvirt
}

func NewLibvirtDomainClient(socketPath string) (*LibvirtDomainClient, error) {
	c, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("potscheduler: dial libvirt %s: %w", socketPath, err)
	}
	l := golibvirt.New(c)
	if err := l.Connect(); err != nil {
		return nil, fmt.Errorf("potscheduler: libvirt connect: %w", err)
	}
	return &LibvirtDomainClient{l: l}, nil
}

func (lc *LibvirtDomainClient) Define(xml string) error {
	_, err := lc.l.DomainDefineXML(xml)
	return err
}

func (lc *LibvirtDomainClient) Start(name string) error {
	dom, err := lc.l.DomainLookupByName(name)
	if err != nil {
		return err
	}
	return lc.l.DomainCreate(dom)
}

func (lc *LibvirtDomainClient) Stop(name string) error {
	dom, err := lc.l.DomainLookupByName(name)
	if err != nil {
		return err
	}
	return lc.l.DomainShutdown(dom)
}

func (lc *LibvirtDomainClient) Destroy(name string) error {
	dom, err := lc.l.DomainLookupByName(name)
	if err != nil {
		return err
	}
	return lc.l.DomainDestroy(dom)
}

func (lc *LibvirtDomainClient) Undefine(name string) error {
	dom, err := lc.l.DomainLookupByName(name)
	if err != nil {
		return err
	}
	return lc.l.DomainUndefine(dom)
}

func (lc *LibvirtDomainClient) Exists(name string) (bool, error) {
	if _, err := lc.l.DomainLookupByName(name); err != nil {
		if strings.Contains(err.Error(), "Domain not found") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// DefineNWFilter installs the pot nwfilter, replacing any older copy
// already in libvirt. Filters live in the kernel and persist across
// controller restarts, which is what gives us the fail-closed property
// — the rules stay in force even if this binary dies. libvirt rejects
// NwfilterDefineXML if a filter with the same name already exists, so
// we undefine first to keep the in-binary rules canonical.
func (lc *LibvirtDomainClient) DefineNWFilter(xml string) error {
	if existing, err := lc.l.NwfilterLookupByName(PotFilterName); err == nil {
		if err := lc.l.NwfilterUndefine(existing); err != nil {
			return fmt.Errorf("undefine existing nwfilter %s: %w", PotFilterName, err)
		}
	} else if !strings.Contains(err.Error(), "not found") {
		return fmt.Errorf("lookup nwfilter %s: %w", PotFilterName, err)
	}
	_, err := lc.l.NwfilterDefineXML(xml)
	return err
}

func (lc *LibvirtDomainClient) Close() {
	_ = lc.l.Disconnect()
}

func (lc *LibvirtDomainClient) InterfaceStats(domName, device string) (rxPackets, txPackets int64, err error) {
	dom, err := lc.l.DomainLookupByName(domName)
	if err != nil {
		return 0, 0, err
	}
	_, rx, _, _, _, tx, _, _, err := lc.l.DomainInterfaceStats(dom, device)
	return rx, tx, err
}

// PotFilterName is the libvirt nwfilter applied to every pot interface.
// Default-deny outbound, inbound permitted so attackers can reach the
// decoy. Because libvirt enforces this in the host kernel via
// ebtables/nftables, the policy stays in force even if the controller
// dies.
const PotFilterName = "shadowtrap-pot"

const potFilterXML = `<filter name='` + PotFilterName + `' chain='root'>
  <!-- Compose libvirt's built-in spoofing protections. Both filters
       reject frames whose source MAC (or ARP source MAC) doesn't match
       the NIC's configured MAC, so a compromised pot can't impersonate
       another host on the L2 segment. -->
  <filterref filter='no-mac-spoofing'/>
  <filterref filter='no-arp-spoofing'/>

  <!-- ARP must flow both ways so the pot is reachable by IP. -->
  <rule action='accept' direction='inout' priority='100'>
    <arp/>
  </rule>

  <!-- Inbound ICMP echo-request and outbound echo-reply: allowed.
       Anything else falls through to the priority-1000 drop. -->
  <rule action='accept' direction='in' priority='200'>
    <icmp type='8'/>
  </rule>
  <rule action='accept' direction='out' priority='210'>
    <icmp type='0'/>
  </rule>

  <!-- Inbound TCP to any port: let the attacker hit the honeypot. -->
  <rule action='accept' direction='in' priority='300'>
    <tcp/>
  </rule>
  <!-- Outbound TCP only on flows already established (i.e. replies). -->
  <rule action='accept' direction='out' priority='310'>
    <tcp state='ESTABLISHED,RELATED'/>
  </rule>
  <!-- Explicit drop for pot-initiated TCP. The catch-all below would
       drop these too, but stating it gives operators a kernel-side
       counter for forensics. -->
  <rule action='drop' direction='out' priority='315'>
    <tcp state='NEW'/>
  </rule>

  <!-- Same shape for UDP. -->
  <rule action='accept' direction='in' priority='400'>
    <udp/>
  </rule>
  <rule action='accept' direction='out' priority='410'>
    <udp state='ESTABLISHED,RELATED'/>
  </rule>
  <rule action='drop' direction='out' priority='415'>
    <udp state='NEW'/>
  </rule>

  <!-- IPv6 is out of scope. Without an explicit drop a guest's
       link-local autoconfig would let an attacker initiate IPv6 flows
       the IPv4 stateful rules can't see. -->
  <rule action='drop' direction='inout' priority='500'>
    <all-ipv6/>
  </rule>

  <!-- Catch-all: anything not explicitly accepted — exotic
       EtherTypes, raw-socket frames, anything else we've missed. -->
  <rule action='drop' direction='inout' priority='1000'/>
</filter>`

// PotFilterXML returns the default-deny egress filter definition.
func PotFilterXML() string { return potFilterXML }

// DomainXMLParams holds the parameters for rendering a pot domain XML.
//
// The pot's NIC attaches as a tap on a controller-managed Linux bridge
// rather than a macvtap on the parent NIC — macvtap has well-known
// issues attaching to a bridged parent and around host↔guest
// connectivity. See netmgr/bridge.go.
type DomainXMLParams struct {
	Name       string
	UUID       string // libvirt UUID; also used as SMBIOS system UUID
	DiskPath   string
	MAC        string
	Bridge     string // Linux bridge name (created by netmgr.EnsureBridge)
	SocketPath string
	FilterName string // libvirt nwfilter applied to the NIC
}

var domainTmpl = template.Must(template.New("domain").Parse(`<domain type='kvm'>
  <name>{{.Name}}</name>
  <uuid>{{.UUID}}</uuid>
  <memory unit='MiB'>512</memory>
  <vcpu>1</vcpu>
  <os>
    <type arch='x86_64' machine='pc-q35-8.2'>hvm</type>
    <boot dev='hd'/>
    <smbios mode='sysinfo'/>
  </os>
  <sysinfo type='smbios'>
    <system>
      <entry name='uuid'>{{.UUID}}</entry>
    </system>
  </sysinfo>
  <features><acpi/><apic/></features>
  <cpu mode='host-model'/>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='{{.DiskPath}}'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='bridge'>
      <source bridge='{{.Bridge}}'/>
      <mac address='{{.MAC}}'/>
      <model type='virtio'/>
      <filterref filter='{{.FilterName}}'/>
    </interface>
    <channel type='unix'>
      <source mode='bind' path='{{.SocketPath}}'/>
      <target type='virtio' name='shadowtrap.serial.0'/>
    </channel>
    <serial type='pty'><target port='0'/></serial>
    <console type='pty'><target type='serial' port='0'/></console>
  </devices>
</domain>`))

func RenderDomainXML(p DomainXMLParams) (string, error) {
	if p.FilterName == "" {
		p.FilterName = PotFilterName
	}
	var buf bytes.Buffer
	if err := domainTmpl.Execute(&buf, p); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// RandomMAC returns a 6-byte MAC carrying the ShadowTrap pot OUI prefix
// 02:73:74 ("st" in ASCII, with the locally-administered + unicast
// bits set). The host nftables backstop matches on this prefix to find
// pot-originated frames at L2; without it the backstop wouldn't see
// pot traffic at all.
func RandomMAC() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[0], b[1], b[2] = 0x02, 0x73, 0x74
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]), nil
}

// RandomUUID returns a random RFC 4122 v4 UUID.
func RandomUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func CloneDisk(base, dest string) error {
	out, err := exec.Command("qemu-img", "create", "-f", "qcow2",
		"-b", base, "-F", "qcow2", dest).CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SafeName turns a pot ID into something safe to use as a libvirt
// domain name.
func SafeName(potID string) string {
	return strings.NewReplacer("@", "_", ".", "-").Replace(potID)
}
