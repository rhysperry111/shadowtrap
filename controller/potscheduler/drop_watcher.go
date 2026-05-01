package potscheduler

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"shadowtrap/controller/db"
)

// DropWatcher tails /dev/kmsg for the host firewall's "shadowtrap-drop:"
// log entries, matches each one to a pot via the source MAC, and asks
// the scheduler to rebuild that pot immediately.
//
// This is the action half of a confirmed containment breach: the kernel
// has already stopped the offending frame; rebuilding the pot makes
// sure an attacker who got a shell loses it before they can craft a
// second attempt or pivot via something the L4 stateful filter doesn't
// catch (e.g. abusing an existing established session).
type DropWatcher struct {
	events   eventSink
	rebuild  rebuilder
	listPots listPotsFunc
	cacheTTL time.Duration

	mu       sync.RWMutex
	macToPot map[string]db.Pot

	done chan struct{}
}

const (
	dropPrefix = "shadowtrap-drop:"
	kmsgDevice = "/dev/kmsg"
)

// kmsgMAC matches the MAC field nftables logs into dmesg-style
// entries: a 14-byte chain (dst[6] || src[6] || ethertype[2]). We
// extract the source MAC (bytes 7..12) downstream.
var kmsgMAC = regexp.MustCompile(`MAC=((?:[0-9a-f]{2}:){13}[0-9a-f]{2})`)

func NewDropWatcher(events eventSink, rebuild rebuilder, listPots listPotsFunc) *DropWatcher {
	return &DropWatcher{
		events:   events,
		rebuild:  rebuild,
		listPots: listPots,
		cacheTTL: 30 * time.Second,
		macToPot: make(map[string]db.Pot),
		done:     make(chan struct{}),
	}
}

func (w *DropWatcher) Start(ctx context.Context) {
	go w.refreshCacheLoop(ctx)
	go w.tailKmsg(ctx)
}

func (w *DropWatcher) Stop() {
	select {
	case <-w.done:
	default:
		close(w.done)
	}
}

// refreshCacheLoop keeps the MAC -> Pot lookup table fresh so each
// kmsg line can be attributed without a database round trip.
func (w *DropWatcher) refreshCacheLoop(ctx context.Context) {
	ticker := time.NewTicker(w.cacheTTL)
	defer ticker.Stop()

	w.refreshCache(ctx)
	for {
		select {
		case <-ticker.C:
			w.refreshCache(ctx)
		case <-w.done:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (w *DropWatcher) refreshCache(ctx context.Context) {
	pots, err := w.listPots(ctx)
	if err != nil {
		log.Printf("dropwatcher: list pots: %v", err)
		return
	}

	cache := make(map[string]db.Pot, len(pots))
	for _, pot := range pots {
		if pot.Mac == "" {
			continue
		}
		cache[strings.ToLower(pot.Mac)] = pot
	}

	w.mu.Lock()
	w.macToPot = cache
	w.mu.Unlock()
}

// tailKmsg reads /dev/kmsg forever and dispatches every line that
// carries our drop prefix. /dev/kmsg returns one kernel record per
// read; we seek to the end on open so old drops from a previous
// controller run don't replay.
func (w *DropWatcher) tailKmsg(ctx context.Context) {
	f, err := os.Open(kmsgDevice)
	if err != nil {
		log.Printf("dropwatcher: open %s: %v (CAP_SYSLOG required)", kmsgDevice, err)
		return
	}
	defer f.Close()

	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		log.Printf("dropwatcher: seek %s: %v", kmsgDevice, err)
	}

	reader := bufio.NewReader(f)
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		default:
		}

		line, err := reader.ReadString('\n')
		if len(line) > 0 && strings.Contains(line, dropPrefix) {
			w.handleDrop(ctx, line)
		}
		if err == nil {
			continue
		}
		if !errors.Is(err, io.EOF) {
			log.Printf("dropwatcher: read %s: %v", kmsgDevice, err)
		}

		// kmsg returns EOF when the producer is faster than the
		// reader; back off briefly and resume.
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (w *DropWatcher) handleDrop(ctx context.Context, line string) {
	src, ok := extractSourceMAC(line)
	if !ok {
		return
	}

	w.mu.RLock()
	pot, known := w.macToPot[src]
	w.mu.RUnlock()
	if !known {
		// Drop logged for a MAC we don't know — either legitimate
		// traffic on a non-pot host that happens to share the OUI,
		// or a pot the cache hasn't picked up yet. Log it but do
		// nothing.
		log.Printf("dropwatcher: drop from unknown MAC %s", src)
		return
	}

	log.Printf("dropwatcher [%s]: host firewall blocked egress; rebuilding", pot.ID)
	w.recordBreach(ctx, pot, line)

	w.mu.Lock()
	delete(w.macToPot, src)
	w.mu.Unlock()

	if err := w.rebuild(ctx, pot); err != nil {
		log.Printf("dropwatcher [%s]: rebuild: %v", pot.ID, err)
	}
}

// extractSourceMAC pulls the source MAC out of a dmesg-format MAC
// field. The field is dst[6] || src[6] || ethertype[2] (14 bytes); the
// source MAC is at zero-indexed bytes 6..11.
func extractSourceMAC(line string) (string, bool) {
	m := kmsgMAC.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	parts := strings.Split(m[1], ":")
	if len(parts) != 14 {
		return "", false
	}
	return strings.ToLower(strings.Join(parts[6:12], ":")), true
}

func (w *DropWatcher) recordBreach(ctx context.Context, pot db.Pot, kmsgLine string) {
	data, _ := json.Marshal(map[string]any{
		"layer": "host_firewall",
		"kmsg":  strings.TrimSpace(kmsgLine),
	})
	_, err := w.events.CreateEvent(ctx, db.CreateEventParams{
		PotID:   pot.ID,
		Time:    time.Now().UTC(),
		Service: "containment",
		Kind:    "egress_blocked",
		Source:  "drop_watcher",
		Data:    data,
	})
	if err != nil {
		log.Printf("dropwatcher [%s]: log event: %v", pot.ID, err)
	}
}
