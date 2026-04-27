package config

import (
	"encoding/json"
	"fmt"
)

type ServiceType string

const (
	ServiceSSH      ServiceType = "ssh"
	ServiceFTP      ServiceType = "ftp"
	ServiceHTTP     ServiceType = "http"
	ServiceSMB      ServiceType = "smb"
	ServiceTelnet   ServiceType = "telnet"
	ServiceMySQL    ServiceType = "mysql"
	ServicePostgres ServiceType = "postgres"
	ServiceRDP      ServiceType = "rdp"
)

// ServiceSpec describes one service the agent should observe. Port is
// metadata that ends up in emitted events — the real daemon binds it,
// not the agent. Path overrides the default Ubuntu log path; leave it
// empty to let the registry pick.
type ServiceSpec struct {
	Type ServiceType `json:"type"`
	Port uint16      `json:"port"`
	Path string      `json:"path,omitempty"`
}

// AgentConfig is sent from the controller via MsgConfig.
//
// Hostname / MachineID / AdminUser / AdminPass form the per-pot identity.
// On reconnect (i.e. an agent that crashed and came back) the controller
// leaves them empty so the running pot keeps its existing credentials —
// rotating them mid-flight would defeat the non-reuse guarantee.
type AgentConfig struct {
	Hostname  string        `json:"hostname,omitempty"`
	MachineID string        `json:"machine_id,omitempty"`
	AdminUser string        `json:"admin_user,omitempty"`
	AdminPass string        `json:"admin_pass,omitempty"`
	Services  []ServiceSpec `json:"services"`
}

func ParseConfig(data []byte) (AgentConfig, error) {
	var cfg AgentConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return AgentConfig{}, fmt.Errorf("config: unmarshal: %w", err)
	}

	for _, svc := range cfg.Services {
		if !validServiceType(svc.Type) {
			return AgentConfig{}, fmt.Errorf("config: unknown service type %q", svc.Type)
		}
		if svc.Port == 0 {
			return AgentConfig{}, fmt.Errorf("config: service %q has zero port", svc.Type)
		}
	}
	return cfg, nil
}

func validServiceType(t ServiceType) bool {
	switch t {
	case ServiceSSH, ServiceFTP, ServiceHTTP, ServiceSMB,
		ServiceTelnet, ServiceMySQL, ServicePostgres, ServiceRDP:
		return true
	}
	return false
}

func (c AgentConfig) Marshal() ([]byte, error) {
	return json.Marshal(c)
}
