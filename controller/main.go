package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"shadowtrap/controller/api"
	"shadowtrap/controller/db"
	"shadowtrap/controller/events"
	"shadowtrap/controller/netmgr"
	"shadowtrap/controller/potmgr"
	"shadowtrap/controller/potscheduler"
	"shadowtrap/controller/ui"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	dsn := flag.String("db", os.Getenv("SHADOWTRAP_DB_DSN"), "postgres DSN (or SHADOWTRAP_DB_DSN env)")
	masterKey := flag.String("api-key", os.Getenv("SHADOWTRAP_API_KEY"), "admin master key (or SHADOWTRAP_API_KEY env)")
	imagesDir := flag.String("images-dir", "/var/lib/shadowtrap/images", "base VM image directory")
	runDir := flag.String("run-dir", "/run/shadowtrap", "runtime directory for pot sockets")
	libvirtSock := flag.String("libvirt", "/var/run/libvirt/libvirt-sock", "libvirt Unix socket path")
	interval := flag.Duration("interval", 30*time.Second, "scheduler reconcile interval")
	flag.Parse()

	if *dsn == "" {
		log.Fatal("--db or SHADOWTRAP_DB_DSN is required")
	}

	// QEMU usually runs as a separate user (the `qemu` user) and cannot
	// traverse $XDG_RUNTIME_DIR (mode 0700, owned by the invoking user).
	// A pot disk under /run/user/... triggers a confusing "Permission
	// denied" buried deep in libvirt — catch it here and point at the fix.
	if strings.HasPrefix(*runDir, "/run/user/") {
		log.Fatalf("--run-dir %s is under $XDG_RUNTIME_DIR, which QEMU "+
			"cannot access. Either set --run-dir to a path readable by the qemu "+
			"user (e.g. /var/lib/shadowtrap/run, chown <you>:qemu, chmod 0750), "+
			"or set user/group in /etc/libvirt/qemu.conf to your own user and "+
			"restart libvirtd.", *runDir)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := db.Open(ctx, *dsn)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer pool.Close()
	queries := db.New(pool)

	// One libvirt connection per driver, sharing the same socket.
	domains, err := potscheduler.NewLibvirtDomainClient(*libvirtSock)
	if err != nil {
		log.Fatalf("libvirt domain client: %v", err)
	}
	netClient, err := netmgr.NewLibvirtNetworkClient(*libvirtSock)
	if err != nil {
		log.Fatalf("libvirt network client: %v", err)
	}

	networks := netmgr.New(netClient, *imagesDir, *runDir)
	pots := potmgr.New()
	scheduler := potscheduler.New(queries, domains, networks, pots, *runDir, *interval)
	eventMgr := events.New(queries)

	// Bootstrap is fail-closed: if the pot nwfilter or host firewall
	// can't be installed, refuse to start. Running uncontained is not
	// an acceptable fallback.
	if err := scheduler.Bootstrap(); err != nil {
		log.Fatalf("scheduler bootstrap: %v", err)
	}

	seedInterfaces(ctx, queries, networks)
	reconnectExistingPots(ctx, queries, networks, pots)

	go eventMgr.Run(ctx, pots)

	scheduler.Start()

	server := newHTTPServer(*addr, queries, scheduler, *masterKey)
	go func() {
		log.Printf("listening on %s", *addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http: %v", err)
		}
	}()

	awaitShutdown()
	log.Println("shutdown signal received")

	scheduler.Stop()
	pots.Close()
	cancel()

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	if err := server.Shutdown(shutCtx); err != nil {
		log.Printf("http shutdown: %v", err)
	}
}

// seedInterfaces snapshots the host's NICs into the database so the UI
// has something to show before the operator configures anything.
func seedInterfaces(ctx context.Context, queries *db.Queries, networks *netmgr.Manager) {
	interfaces, err := networks.ScanInterfaces()
	if err != nil {
		log.Printf("warning: interface scan: %v", err)
		return
	}
	for _, iface := range interfaces {
		_ = queries.UpsertInterface(ctx, db.UpsertInterfaceParams{
			ID:      iface.ID,
			Enabled: iface.Enabled,
			Link:    iface.Link,
			Mode:    "standalone",
		})
	}
}

// reconnectExistingPots reattaches potmgr to pots that survived a
// controller restart. Identity is left zero on purpose: if the agent
// re-sends HELLO after a crash, we hand it the same config it already
// has rather than fresh credentials.
func reconnectExistingPots(ctx context.Context, queries *db.Queries, networks *netmgr.Manager, pots *potmgr.Manager) {
	existing, err := queries.ListPots(ctx)
	if err != nil {
		return
	}
	for _, pot := range existing {
		image, err := queries.GetImage(ctx, pot.ImageID)
		if err != nil {
			continue
		}
		domainName := potscheduler.SafeName(pot.ID)
		socketPath := networks.SocketPath(domainName)
		if err := pots.Connect(pot.ID, socketPath, featuresFromImage(image), potmgr.Identity{}); err != nil {
			log.Printf("startup: reconnect %s: %v", pot.ID, err)
		}
	}
}

func newHTTPServer(addr string, queries *db.Queries, scheduler *potscheduler.Scheduler, masterKey string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/api/", api.New(queries, scheduler, masterKey))
	mux.Handle("/", ui.Handler())

	return &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

func awaitShutdown() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
}

func featuresFromImage(image db.Image) []potmgr.Feature {
	parsed, _ := db.ParseFeatures(image.Features)
	out := make([]potmgr.Feature, len(parsed))
	for i, feature := range parsed {
		out[i] = potmgr.Feature{Name: feature.Name}
	}
	return out
}
