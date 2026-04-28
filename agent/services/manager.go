// Package services manages the lifecycle of honeypot service observers.
package services

import (
	"context"
	"fmt"
	"log"
	"sync"

	"shadowtrap/agent/config"
	"shadowtrap/agent/events"
)

// Service is the contract every observer satisfies.
type Service interface {
	Name() string
	Start(ctx context.Context) error
	Stop() error
}

// Manager keeps the running set of services in sync with whatever the
// controller most recently asked for.
type Manager struct {
	streamer *events.Streamer

	mu        sync.Mutex
	running   map[string]Service
	cancels   map[string]context.CancelFunc
	adminUser string
	adminPass string
}

func NewManager(streamer *events.Streamer) *Manager {
	return &Manager{
		streamer: streamer,
		running:  make(map[string]Service),
		cancels:  make(map[string]context.CancelFunc),
	}
}

// AdminCredentials returns the admin credential pair currently in effect.
// The provisioning hook inside a pot uses this to push the same pair into
// the underlying daemon (e.g. via chpasswd) so the attacker sees what the
// controller advertised.
func (m *Manager) AdminCredentials() (user, pass string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.adminUser, m.adminPass
}

// Apply reconciles the running set against cfg. Services in cfg but not
// running are started; services running but no longer in cfg are stopped.
//
// Identity fields (hostname, machine-id, admin credentials) only get
// applied when present. The controller omits them on the reconnect path,
// which keeps a restarted agent on its existing identity.
func (m *Manager) Apply(cfg config.AgentConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.applyIdentity(cfg)
	m.stopRemoved(cfg.Services)
	return m.startAdded(cfg.Services)
}

func (m *Manager) applyIdentity(cfg config.AgentConfig) {
	if cfg.Hostname != "" {
		applyHostname(cfg.Hostname)
	}
	if cfg.MachineID != "" {
		applyMachineID(cfg.MachineID)
	}
	if cfg.AdminUser != "" && cfg.AdminPass != "" {
		m.adminUser = cfg.AdminUser
		m.adminPass = cfg.AdminPass
	}
}

func (m *Manager) stopRemoved(specs []config.ServiceSpec) {
	wanted := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		wanted[specKey(spec)] = struct{}{}
	}
	for key, svc := range m.running {
		if _, ok := wanted[key]; ok {
			continue
		}
		m.stop(key, svc)
	}
}

func (m *Manager) startAdded(specs []config.ServiceSpec) error {
	for _, spec := range specs {
		key := specKey(spec)
		if _, alreadyRunning := m.running[key]; alreadyRunning {
			continue
		}

		svc, err := newService(spec, m.streamer)
		if err != nil {
			return fmt.Errorf("services: create %s: %w", key, err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		m.running[key] = svc
		m.cancels[key] = cancel

		go func(svc Service, key string) {
			if err := svc.Start(ctx); err != nil {
				log.Printf("services: %s exited: %v", key, err)
			}
		}(svc, key)
	}
	return nil
}

// StopAll halts every running service. Called on shutdown.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, svc := range m.running {
		m.stop(key, svc)
	}
}

func (m *Manager) stop(key string, svc Service) {
	if cancel, ok := m.cancels[key]; ok {
		cancel()
		delete(m.cancels, key)
	}
	if err := svc.Stop(); err != nil {
		log.Printf("services: stop %s: %v", key, err)
	}
	delete(m.running, key)
}

func specKey(spec config.ServiceSpec) string {
	return fmt.Sprintf("%s:%d", spec.Type, spec.Port)
}
