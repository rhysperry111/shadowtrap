package netmgr

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"text/template"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// NetworkClient is the slice of libvirt's network API we depend on.
type NetworkClient interface {
	DefineNetwork(xml string) error
	StartNetwork(name string) error
	DestroyNetwork(name string) error
	UndefineNetwork(name string) error
	NetworkExists(name string) (bool, error)
}

// LibvirtNetworkClient is the production NetworkClient.
type LibvirtNetworkClient struct {
	l *golibvirt.Libvirt
}

func NewLibvirtNetworkClient(socketPath string) (*LibvirtNetworkClient, error) {
	c, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("netmgr: dial libvirt %s: %w", socketPath, err)
	}
	l := golibvirt.New(c)
	if err := l.Connect(); err != nil {
		return nil, fmt.Errorf("netmgr: libvirt connect: %w", err)
	}
	return &LibvirtNetworkClient{l: l}, nil
}

func (lc *LibvirtNetworkClient) DefineNetwork(xml string) error {
	_, err := lc.l.NetworkDefineXML(xml)
	return err
}

func (lc *LibvirtNetworkClient) StartNetwork(name string) error {
	n, err := lc.l.NetworkLookupByName(name)
	if err != nil {
		return err
	}
	return lc.l.NetworkCreate(n)
}

func (lc *LibvirtNetworkClient) DestroyNetwork(name string) error {
	n, err := lc.l.NetworkLookupByName(name)
	if err != nil {
		return err
	}
	return lc.l.NetworkDestroy(n)
}

func (lc *LibvirtNetworkClient) UndefineNetwork(name string) error {
	n, err := lc.l.NetworkLookupByName(name)
	if err != nil {
		return err
	}
	return lc.l.NetworkUndefine(n)
}

func (lc *LibvirtNetworkClient) NetworkExists(name string) (bool, error) {
	if _, err := lc.l.NetworkLookupByName(name); err != nil {
		if strings.Contains(err.Error(), "Network not found") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (lc *LibvirtNetworkClient) Close() {
	_ = lc.l.Disconnect()
}

// NetworkXMLParams holds the parameters for a libvirt bridge network.
type NetworkXMLParams struct {
	Name      string
	Bridge    string
	Interface string
	VLANID    int32 // 0 means no VLAN tagging
}

var networkTmpl = template.Must(template.New("network").Parse(`<network>
  <name>{{.Name}}</name>
  <forward mode='bridge'/>
  <bridge name='{{.Bridge}}'/>
  {{- if gt .VLANID 0}}
  <vlan trunk='no'>
    <tag id='{{.VLANID}}'/>
  </vlan>
  {{- end}}
</network>`))

func RenderNetworkXML(p NetworkXMLParams) (string, error) {
	var buf bytes.Buffer
	if err := networkTmpl.Execute(&buf, p); err != nil {
		return "", err
	}
	return buf.String(), nil
}
