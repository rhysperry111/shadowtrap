// Package protocol defines the wire format for agent <-> central messages
// over a virtual serial port.
//
// Each frame is a 4-byte header followed by an optional payload:
//
//	[type:1][len_hi:1][len_lo:1][checksum:1][payload:N]
//
// The checksum is the XOR of the three header bytes before it. The header
// is fully validated before any payload is allocated, so a corrupt or
// hostile peer cannot trick us into reserving large buffers.
package protocol

import (
	"errors"
	"fmt"
	"io"
)

const (
	HeaderSize     = 4
	MaxPayloadSize = 4096
)

// Message types. Values are part of the wire format and must not change.
const (
	MsgHello     byte = 0x01 // agent -> central, payload = agent ID
	MsgAck       byte = 0x02 // central -> agent, empty
	MsgConfig    byte = 0x03 // central -> agent, payload = JSON AgentConfig
	MsgEvent     byte = 0x04 // agent -> central, payload = JSON Event
	MsgHeartbeat byte = 0x05 // agent -> central, empty
	MsgNack      byte = 0x06 // central -> agent, empty
)

var (
	ErrInvalidChecksum = errors.New("protocol: invalid checksum")
	ErrPayloadTooLarge = errors.New("protocol: payload exceeds maximum size")
	ErrUnknownMsgType  = errors.New("protocol: unknown message type")
)

type Message struct {
	Type    byte
	Payload []byte
}

func checksum(msgType, lengthHi, lengthLo byte) byte {
	return msgType ^ lengthHi ^ lengthLo
}

// Write encodes msg and sends it on w. Callers must serialise concurrent
// writes themselves; the transport layer holds a mutex for this.
func Write(w io.Writer, msg Message) error {
	if len(msg.Payload) > MaxPayloadSize {
		return ErrPayloadTooLarge
	}

	length := uint16(len(msg.Payload))
	hi := byte(length >> 8)
	lo := byte(length & 0xff)

	header := [HeaderSize]byte{msg.Type, hi, lo, checksum(msg.Type, hi, lo)}
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("protocol: write header: %w", err)
	}
	if length > 0 {
		if _, err := w.Write(msg.Payload); err != nil {
			return fmt.Errorf("protocol: write payload: %w", err)
		}
	}
	return nil
}

// Read decodes a single message from r, rejecting malformed frames before
// allocating any payload buffer.
func Read(r io.Reader) (Message, error) {
	var header [HeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Message{}, fmt.Errorf("protocol: read header: %w", err)
	}

	msgType, hi, lo, sum := header[0], header[1], header[2], header[3]

	if sum != checksum(msgType, hi, lo) {
		return Message{}, ErrInvalidChecksum
	}

	switch msgType {
	case MsgHello, MsgAck, MsgConfig, MsgEvent, MsgHeartbeat, MsgNack:
		// known type, fall through
	default:
		return Message{}, ErrUnknownMsgType
	}

	length := (uint16(hi) << 8) | uint16(lo)
	if length > MaxPayloadSize {
		return Message{}, ErrPayloadTooLarge
	}

	if length == 0 {
		return Message{Type: msgType}, nil
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Message{}, fmt.Errorf("protocol: read payload: %w", err)
	}
	return Message{Type: msgType, Payload: payload}, nil
}
