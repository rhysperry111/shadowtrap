package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"shadowtrap/agent/config"
	"shadowtrap/agent/events"
	"shadowtrap/agent/protocol"
	"shadowtrap/agent/services"
	"shadowtrap/agent/transport"
)

const heartbeatInterval = 30 * time.Second

func main() {
	devicePath := flag.String("serial", "/dev/vport0p0", "virtio-serial device path")
	agentID := flag.String("id", hostname(), "agent identifier sent in HELLO")
	flag.Parse()

	serial, err := transport.Open(*devicePath)
	if err != nil {
		log.Fatalf("fatal: %v", err)
	}
	defer serial.Close()

	streamer := events.NewStreamer(256)
	defer streamer.Close()

	manager := services.NewManager(streamer)
	defer manager.StopAll()

	if err := serial.Send(protocol.Message{
		Type:    protocol.MsgHello,
		Payload: []byte(*agentID),
	}); err != nil {
		log.Fatalf("send HELLO: %v", err)
	}

	go readMessages(serial, manager)
	go forwardEvents(serial, streamer)
	go sendHeartbeats(serial)

	waitForSignal()
	log.Println("shutdown signal received")
}

func readMessages(serial *transport.Serial, manager *services.Manager) {
	for {
		msg, err := serial.Recv()
		if err != nil {
			log.Printf("recv: %v", err)
			time.Sleep(time.Second)
			continue
		}

		switch msg.Type {
		case protocol.MsgConfig:
			applyConfig(serial, manager, msg.Payload)
		case protocol.MsgAck, protocol.MsgNack:
			// responses to our own writes; nothing to do
		default:
			log.Printf("unexpected message type 0x%02x", msg.Type)
		}
	}
}

func applyConfig(serial *transport.Serial, manager *services.Manager, payload []byte) {
	cfg, err := config.ParseConfig(payload)
	if err != nil {
		log.Printf("bad config: %v", err)
		_ = serial.Send(protocol.Message{Type: protocol.MsgNack})
		return
	}
	if err := manager.Apply(cfg); err != nil {
		log.Printf("apply config: %v", err)
		_ = serial.Send(protocol.Message{Type: protocol.MsgNack})
		return
	}
	_ = serial.Send(protocol.Message{Type: protocol.MsgAck})
}

func forwardEvents(serial *transport.Serial, streamer *events.Streamer) {
	for event := range streamer.Events() {
		payload, err := event.Marshal()
		if err != nil {
			log.Printf("marshal event: %v", err)
			continue
		}
		err = serial.Send(protocol.Message{
			Type:    protocol.MsgEvent,
			Payload: payload,
		})
		if err != nil {
			log.Printf("send event: %v", err)
		}
	}
}

func sendHeartbeats(serial *transport.Serial) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for range ticker.C {
		if err := serial.Send(protocol.Message{Type: protocol.MsgHeartbeat}); err != nil {
			log.Printf("send heartbeat: %v", err)
		}
	}
}

func waitForSignal() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}
