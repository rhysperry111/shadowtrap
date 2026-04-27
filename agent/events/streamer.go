// Package events carries activity reports from services back to the
// transport layer.
package events

import (
	"encoding/json"
	"time"
)

type Kind string

const (
	KindConnection Kind = "connection"
	KindAuth       Kind = "auth"
	KindCommand    Kind = "command"
	KindData       Kind = "data"
	KindDisconnect Kind = "disconnect"
)

type Event struct {
	Time    time.Time         `json:"time"`
	Service string            `json:"service"`
	Kind    Kind              `json:"kind"`
	Source  string            `json:"source"`
	Data    map[string]string `json:"data,omitempty"`
}

func (e Event) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

// Streamer is a buffered, drop-on-full event channel. Services should
// never block on emit — the worst that can happen is we lose an event
// when the controller is slow to drain.
type Streamer struct {
	ch chan Event
}

func NewStreamer(bufSize int) *Streamer {
	return &Streamer{ch: make(chan Event, bufSize)}
}

func (s *Streamer) Emit(e Event) {
	select {
	case s.ch <- e:
	default:
		// buffer full; drop rather than stall the producer
	}
}

func (s *Streamer) Events() <-chan Event {
	return s.ch
}

func (s *Streamer) Close() {
	close(s.ch)
}
