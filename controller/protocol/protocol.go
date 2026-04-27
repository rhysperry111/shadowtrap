// Package protocol is the host side of the agent <-> central wire
// format. The frame layout matches the agent's package of the same
// name; see agent/protocol for the full description.
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

const (
	MsgHello     byte = 0x01
	MsgAck       byte = 0x02
	MsgConfig    byte = 0x03
	MsgEvent     byte = 0x04
	MsgHeartbeat byte = 0x05
	MsgNack      byte = 0x06
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
		// known type
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
