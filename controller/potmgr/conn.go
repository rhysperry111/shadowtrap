package potmgr

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"sync"
	"time"

	"shadowtrap/controller/protocol"
)

const heartbeatTimeout = 90 * time.Second

// Feature describes one piece of software baked into a pot image.
type Feature struct {
	Name string `json:"name"`
}

// Identity is the per-pot secret bundle the agent applies on first
// contact. Hostname and MachineID exist to vary fingerprintable surface
// across cloned pots; AdminUser/AdminPass give each pot its own
// credential pair so a stolen one isn't reusable elsewhere.
type Identity struct {
	Hostname  string
	MachineID string
	AdminUser string
	AdminPass string
}

// Event is a security event received from a running pot agent.
type Event struct {
	PotID   string
	Time    time.Time
	Service string
	Kind    string
	Source  string
	Data    map[string]string
}

type agentService struct {
	Type string `json:"type"`
	Port uint16 `json:"port"`
	Path string `json:"path,omitempty"`
}

type agentConfig struct {
	Hostname  string         `json:"hostname,omitempty"`
	MachineID string         `json:"machine_id,omitempty"`
	AdminUser string         `json:"admin_user,omitempty"`
	AdminPass string         `json:"admin_pass,omitempty"`
	Services  []agentService `json:"services"`
}

// featureServices maps an image feature name to the service the agent
// observes for it. Several feature names can resolve to the same
// service type with different log paths — apache2 and nginx are both
// HTTP, but they tail different access logs. Where Path is empty the
// agent falls back to its default for the type.
var featureServices = map[string]agentService{
	"openssh":    {Type: "ssh", Port: 22, Path: "/var/log/auth.log"},
	"ssh":        {Type: "ssh", Port: 22, Path: "/var/log/auth.log"},
	"apache2":    {Type: "http", Port: 80, Path: "/var/log/apache2/access.log"},
	"nginx":      {Type: "http", Port: 80, Path: "/var/log/nginx/access.log"},
	"http":       {Type: "http", Port: 80},
	"samba":      {Type: "smb", Port: 445, Path: "/var/log/samba/log.smbd"},
	"smb":        {Type: "smb", Port: 445},
	"telnet":     {Type: "telnet", Port: 23, Path: "/var/log/auth.log"},
	"telnetd":    {Type: "telnet", Port: 23, Path: "/var/log/auth.log"},
	"vsftpd":     {Type: "ftp", Port: 21, Path: "/var/log/vsftpd.log"},
	"ftp":        {Type: "ftp", Port: 21},
	"mysql":      {Type: "mysql", Port: 3306, Path: "/var/log/mysql/error.log"},
	"mariadb":    {Type: "mysql", Port: 3306, Path: "/var/log/mysql/error.log"},
	"postgresql": {Type: "postgres", Port: 5432},
	"postgres":   {Type: "postgres", Port: 5432},
	"xrdp":       {Type: "rdp", Port: 3389, Path: "/var/log/xrdp.log"},
	"rdp":        {Type: "rdp", Port: 3389},
}

func configFromFeatures(features []Feature, identity Identity) agentConfig {
	seen := map[string]bool{}
	var services []agentService

	for _, feature := range features {
		svc, known := featureServices[feature.Name]
		if !known || seen[svc.Type] {
			continue
		}
		services = append(services, svc)
		seen[svc.Type] = true
	}

	return agentConfig{
		Hostname:  identity.Hostname,
		MachineID: identity.MachineID,
		AdminUser: identity.AdminUser,
		AdminPass: identity.AdminPass,
		Services:  services,
	}
}

// conn is the live virtio-serial channel to a single agent.
type conn struct {
	potID  string
	socket net.Conn
	sendMu sync.Mutex

	heartbeatMu   sync.RWMutex
	lastHeartbeat time.Time

	cancel context.CancelFunc
}

func newConn(potID, socketPath string, features []Feature, identity Identity, events chan<- Event) (*conn, error) {
	socket, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &conn{
		potID:         potID,
		socket:        socket,
		lastHeartbeat: time.Now(),
		cancel:        cancel,
	}

	go c.run(ctx, configFromFeatures(features, identity), events)
	return c, nil
}

// run reads frames from the agent and dispatches them by type until the
// connection drops or the context is cancelled.
func (c *conn) run(ctx context.Context, config agentConfig, events chan<- Event) {
	defer c.socket.Close()

	for {
		msg, err := protocol.Read(c.socket)
		if err != nil {
			select {
			case <-ctx.Done():
				// shutdown path; the read error is expected
			default:
				log.Printf("potmgr [%s]: recv: %v", c.potID, err)
			}
			return
		}

		switch msg.Type {
		case protocol.MsgHello:
			if err := c.sendConfig(config); err != nil {
				log.Printf("potmgr [%s]: send config: %v", c.potID, err)
			}
		case protocol.MsgHeartbeat:
			c.markHeartbeat()
		case protocol.MsgEvent:
			c.handleEvent(msg.Payload, events)
		case protocol.MsgAck, protocol.MsgNack:
			// control responses, not events
		default:
			log.Printf("potmgr [%s]: unexpected msg 0x%02x", c.potID, msg.Type)
		}
	}
}

func (c *conn) markHeartbeat() {
	c.heartbeatMu.Lock()
	c.lastHeartbeat = time.Now()
	c.heartbeatMu.Unlock()
}

func (c *conn) sendConfig(config agentConfig) error {
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return protocol.Write(c.socket, protocol.Message{
		Type:    protocol.MsgConfig,
		Payload: data,
	})
}

// handleEvent decodes one EVENT frame and forwards it on the manager
// channel. If the channel is full we drop the event rather than block
// the read side — stalling here would block heartbeats too.
func (c *conn) handleEvent(payload []byte, events chan<- Event) {
	var raw struct {
		Time    time.Time         `json:"time"`
		Service string            `json:"service"`
		Kind    string            `json:"kind"`
		Source  string            `json:"source"`
		Data    map[string]string `json:"data"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		log.Printf("potmgr [%s]: bad event payload: %v", c.potID, err)
		return
	}

	event := Event{
		PotID:   c.potID,
		Time:    raw.Time,
		Service: raw.Service,
		Kind:    raw.Kind,
		Source:  raw.Source,
		Data:    raw.Data,
	}

	select {
	case events <- event:
	default:
		log.Printf("potmgr [%s]: event channel full, dropping", c.potID)
	}
}

func (c *conn) healthy() bool {
	c.heartbeatMu.RLock()
	defer c.heartbeatMu.RUnlock()
	return time.Since(c.lastHeartbeat) < heartbeatTimeout
}

func (c *conn) close() {
	c.cancel()
	c.socket.Close()
}
