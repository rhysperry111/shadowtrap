package services

import (
	"context"
	"fmt"
	"log"

	"shadowtrap/agent/events"
)

// logService observes a real running daemon by tailing its log file.
//
// We deliberately don't run our own listeners — sshd, vsftpd, and friends
// already do that, and shipping a custom emulator across many pots makes
// them all fingerprintable in the same way. Tailing the genuine daemon
// looks just like a regular Ubuntu install on the wire.
type logService struct {
	svcType  string
	port     uint16
	logPath  string
	parser   Parser
	streamer *events.Streamer
}

func newLogService(svcType string, port uint16, logPath string, parser Parser, streamer *events.Streamer) *logService {
	return &logService{
		svcType:  svcType,
		port:     port,
		logPath:  logPath,
		parser:   parser,
		streamer: streamer,
	}
}

func (s *logService) Name() string {
	return fmt.Sprintf("%s:%d", s.svcType, s.port)
}

func (s *logService) Start(ctx context.Context) error {
	log.Printf("services: %s tailing %s", s.Name(), s.logPath)
	newTailer(s.logPath).run(ctx, s.handleLine)
	return nil
}

// Stop is a no-op; cancelling Start's context halts the tailer.
func (s *logService) Stop() error { return nil }

func (s *logService) handleLine(line string) {
	if event, ok := s.parser(line); ok {
		s.streamer.Emit(event)
	}
}
