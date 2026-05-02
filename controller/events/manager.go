// Package events is a thin pump that drains pot events into the
// database. The intent is for it to grow into an incident-correlation
// engine — turning streams of low-level events into higher-level
// findings (e.g. port-scan-then-exploit from a single source) and
// dispatching response actions. For now it just persists.
package events

import (
	"context"
	"encoding/json"

	"shadowtrap/controller/db"
	"shadowtrap/controller/potmgr"
)

type Manager struct {
	queries *db.Queries
}

func New(queries *db.Queries) *Manager {
	return &Manager{queries: queries}
}

// Run consumes events from pots and writes them to the database. It
// returns when the events channel closes or ctx is cancelled.
func (m *Manager) Run(ctx context.Context, pots *potmgr.Manager) {
	for {
		select {
		case event, ok := <-pots.Events():
			if !ok {
				return
			}
			m.persist(ctx, event)
		case <-ctx.Done():
			return
		}
	}
}

func (m *Manager) persist(ctx context.Context, event potmgr.Event) {
	data, _ := json.Marshal(event.Data)
	if data == nil {
		data = []byte("{}")
	}
	_, _ = m.queries.CreateEvent(ctx, db.CreateEventParams{
		PotID:   event.PotID,
		Time:    event.Time,
		Service: event.Service,
		Kind:    event.Kind,
		Source:  event.Source,
		Data:    data,
	})
}
