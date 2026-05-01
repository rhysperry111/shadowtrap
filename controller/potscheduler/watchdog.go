package potscheduler

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"

	"shadowtrap/controller/db"
)

// Containment-watchdog tuning.
//
// The watchdog is a soft, observation-based backstop on top of the
// hard, kernel-enforced nwfilter. The filter prevents unauthorised
// egress from reaching the wire; the watchdog watches for evidence
// that the guest tried anyway, and treats that as a compromise signal
// worth rebuilding the pot over.
const (
	// Initial settle period after provisioning. Counters take a moment
	// to stabilise — early-boot ARP and macvtap chatter can produce a
	// handful of packets that would otherwise trip an alert.
	watchdogGrace = 30 * time.Second

	// Sustained-egress threshold per tick. More than this many
	// guest-initiated packets without matching inbound activity counts
	// as suspicious. The filter has already dropped the packets — we
	// are inferring the attempt.
	watchdogEgressPackets = 8

	// Number of consecutive ticks that need to show the silent-drop
	// pattern before we rebuild. Two is enough to distinguish an ARP
	// blip from an attacker with a shell.
	watchdogConfirmTicks = 2
)

// sampler is the libvirt-facing view the watchdog needs. Tests
// substitute a fake one through the DomainClient interface.
type sampler interface {
	InterfaceStats(domainName, device string) (rxPackets, txPackets int64, err error)
}

// eventSink persists a containment-breach event. Depending only on
// CreateEvent makes the sink swappable in tests.
type eventSink interface {
	CreateEvent(ctx context.Context, arg db.CreateEventParams) (db.Event, error)
}

// rebuilder is the callback the watchdog invokes to tear down a
// breached pot. The reconcile loop replaces it on its next tick.
type rebuilder func(ctx context.Context, pot db.Pot) error

// listPotsFunc is the read side of the database the watchdog needs.
type listPotsFunc func(context.Context) ([]db.Pot, error)

// Watchdog samples per-pot interface counters and rebuilds pots that
// show evidence of attempting unauthorised egress.
type Watchdog struct {
	sampler  sampler
	events   eventSink
	rebuild  rebuilder
	interval time.Duration
	done     chan struct{}

	mu    sync.Mutex
	state map[string]*potState
}

type potState struct {
	provisionedAt time.Time
	lastRx        int64
	lastTx        int64
	lastSeen      time.Time
	confirmCount  int
	initialised   bool
}

func NewWatchdog(s sampler, events eventSink, rebuild rebuilder, interval time.Duration) *Watchdog {
	return &Watchdog{
		sampler:  s,
		events:   events,
		rebuild:  rebuild,
		interval: interval,
		done:     make(chan struct{}),
		state:    make(map[string]*potState),
	}
}

// Track starts monitoring a pot. The scheduler calls this just after
// the domain comes up. Tracking an already-tracked pot is a no-op.
func (w *Watchdog) Track(potID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.state[potID]; ok {
		return
	}
	w.state[potID] = &potState{provisionedAt: time.Now()}
}

// Forget drops tracking state for a destroyed pot.
func (w *Watchdog) Forget(potID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.state, potID)
}

func (w *Watchdog) Start(ctx context.Context, listPots listPotsFunc) {
	go w.sampleLoop(ctx, listPots)
}

func (w *Watchdog) sampleLoop(ctx context.Context, listPots listPotsFunc) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pots, err := listPots(ctx)
			if err != nil {
				log.Printf("watchdog: list pots: %v", err)
				continue
			}
			for _, pot := range pots {
				w.check(ctx, pot)
			}
		case <-w.done:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (w *Watchdog) Stop() {
	select {
	case <-w.done:
	default:
		close(w.done)
	}
}

// check runs one watchdog tick against a single pot: read its tap
// counters, update the rolling state, and rebuild the pot if the
// silent-drop pattern has held for watchdogConfirmTicks in a row.
func (w *Watchdog) check(ctx context.Context, pot db.Pot) {
	if pot.Mac == "" {
		return
	}

	state := w.stateFor(pot)

	rx, tx, err := w.sampler.InterfaceStats(SafeName(pot.ID), pot.Mac)
	if err != nil {
		// Domain may be transitioning; don't act on transient errors.
		if !strings.Contains(err.Error(), "Domain not found") {
			log.Printf("watchdog [%s]: stats: %v", pot.ID, err)
		}
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// First sample: just record the baseline.
	if !state.initialised {
		state.lastRx, state.lastTx = rx, tx
		state.lastSeen = time.Now()
		state.initialised = true
		return
	}

	// Inside the post-provisioning grace window: keep updating the
	// baseline but never alert.
	if time.Since(state.provisionedAt) < watchdogGrace {
		state.lastRx, state.lastTx = rx, tx
		return
	}

	rxDelta := rx - state.lastRx
	txDelta := tx - state.lastTx
	state.lastRx, state.lastTx = rx, tx

	// rx on the tap (from the host's POV) is guest-initiated traffic;
	// tx is traffic delivered to the guest. A pot is only ever
	// supposed to transmit in response to an incoming probe, so
	// guest-initiated packets without matching inbound activity mean
	// the pot tried to start its own flow — which the filter dropped.
	silentDrop := rxDelta > watchdogEgressPackets && txDelta == 0
	if silentDrop {
		state.confirmCount++
	} else {
		state.confirmCount = 0
	}
	if state.confirmCount < watchdogConfirmTicks {
		return
	}

	log.Printf("watchdog [%s]: unauthorised egress pattern (rxΔ=%d txΔ=%d); rebuilding",
		pot.ID, rxDelta, txDelta)

	w.recordBreach(ctx, pot, rxDelta, txDelta, state.confirmCount)
	delete(w.state, pot.ID)

	if err := w.rebuild(ctx, pot); err != nil {
		log.Printf("watchdog [%s]: rebuild: %v", pot.ID, err)
	}
}

// stateFor returns the rolling state for a pot, lazily initialising
// entries for pots the watchdog learned about from the database (e.g.
// after a controller restart) without ever having Track called.
func (w *Watchdog) stateFor(pot db.Pot) *potState {
	w.mu.Lock()
	defer w.mu.Unlock()
	if state, ok := w.state[pot.ID]; ok {
		return state
	}
	state := &potState{provisionedAt: pot.CreatedAt}
	w.state[pot.ID] = state
	return state
}

// recordBreach writes a containment/egress_blocked event so the
// operator can see the watchdog acted and why.
func (w *Watchdog) recordBreach(ctx context.Context, pot db.Pot, rxDelta, txDelta int64, confirmCount int) {
	data, _ := json.Marshal(map[string]any{
		"rx_packet_delta": rxDelta,
		"tx_packet_delta": txDelta,
		"confirm_ticks":   confirmCount,
		"interval":        w.interval.String(),
	})
	_, err := w.events.CreateEvent(ctx, db.CreateEventParams{
		PotID:   pot.ID,
		Time:    time.Now().UTC(),
		Service: "containment",
		Kind:    "egress_blocked",
		Source:  "watchdog",
		Data:    data,
	})
	if err != nil {
		log.Printf("watchdog [%s]: log event: %v", pot.ID, err)
	}
}
