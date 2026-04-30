// Package potmgr keeps the serial connections to running pot agents.
//
// It owns the protocol-level dialogue: greet on first contact with a
// config, track heartbeats, forward events back upstream. There is no
// database dependency here — callers wire events into persistence.
package potmgr

import (
	"fmt"
	"sync"
)

const eventBufSize = 512

// Manager multiplexes connections to all running pot agents.
type Manager struct {
	mu     sync.RWMutex
	conns  map[string]*conn
	events chan Event
}

func New() *Manager {
	return &Manager{
		conns:  make(map[string]*conn),
		events: make(chan Event, eventBufSize),
	}
}

// Connect opens a connection to a pot's virtio-serial socket. The given
// features drive the agent's service config; identity carries the per-pot
// hostname, machine-id, and admin credentials applied before listeners
// come up.
func (m *Manager) Connect(potID, socketPath string, features []Feature, identity Identity) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.conns[potID]; exists {
		return fmt.Errorf("potmgr: already connected to %s", potID)
	}

	c, err := newConn(potID, socketPath, features, identity, m.events)
	if err != nil {
		return fmt.Errorf("potmgr: connect %s: %w", potID, err)
	}
	m.conns[potID] = c
	return nil
}

func (m *Manager) Disconnect(potID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.conns[potID]
	if !ok {
		return
	}
	c.close()
	delete(m.conns, potID)
}

// IsHealthy returns true if the pot has heartbeated within the timeout.
func (m *Manager) IsHealthy(potID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.conns[potID]
	return ok && c.healthy()
}

func (m *Manager) Events() <-chan Event {
	return m.events
}

// Close disconnects every pot and closes the event channel.
func (m *Manager) Close() {
	m.mu.Lock()
	for potID, c := range m.conns {
		c.close()
		delete(m.conns, potID)
	}
	m.mu.Unlock()
	close(m.events)
}
