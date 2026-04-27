// Package transport carries the protocol over the virtio-serial character
// device. Virtio-serial behaves like a plain file from userspace, so no
// termios fiddling is required.
package transport

import (
	"fmt"
	"os"
	"sync"

	"shadowtrap/agent/protocol"
)

// Serial wraps the device. Send is safe to call concurrently; Recv is not
// — there should only ever be one reader goroutine.
type Serial struct {
	f      *os.File
	sendMu sync.Mutex
}

func Open(device string) (*Serial, error) {
	f, err := os.OpenFile(device, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("transport: open %s: %w", device, err)
	}
	return &Serial{f: f}, nil
}

func (s *Serial) Send(msg protocol.Message) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return protocol.Write(s.f, msg)
}

func (s *Serial) Recv() (protocol.Message, error) {
	return protocol.Read(s.f)
}

func (s *Serial) Close() error {
	return s.f.Close()
}
