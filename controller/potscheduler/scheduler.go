// Package potscheduler reconciles desired deployments against running
// pot VMs. It drives libvirt for VM lifecycle and potmgr for the
// agent-side serial dialogue.
package potscheduler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"shadowtrap/controller/db"
	"shadowtrap/controller/netmgr"
	"shadowtrap/controller/potmgr"
)

// Scheduler runs the reconcile loop and the two containment watchers.
type Scheduler struct {
	queries  *db.Queries
	domains  DomainClient
	networks *netmgr.Manager
	pots     *potmgr.Manager
	runDir   string
	interval time.Duration
	done     chan struct{}

	watchdog    *Watchdog
	dropWatcher *DropWatcher
}

func New(
	queries *db.Queries,
	domains DomainClient,
	networks *netmgr.Manager,
	pots *potmgr.Manager,
	runDir string,
	interval time.Duration,
) *Scheduler {
	s := &Scheduler{
		queries:  queries,
		domains:  domains,
		networks: networks,
		pots:     pots,
		runDir:   runDir,
		interval: interval,
		done:     make(chan struct{}),
	}

	// The watchdog samples faster than the reconcile loop — a leaking
	// pot should die in seconds, not at the next 30-second tick.
	s.watchdog = NewWatchdog(domains, queries, s.rebuildBreached, 5*time.Second)

	// The drop watcher reacts to direct evidence (host nftables drop
	// log lines) rather than the watchdog's counter heuristic, so a
	// pot is rebuilt on the very first packet the host firewall blocks.
	s.dropWatcher = NewDropWatcher(queries, s.rebuildBreached, queries.ListPots)

	return s
}

// Bootstrap performs one-time host-side setup that must happen before
// any pot starts. Every step is fail-closed: if any of them fail, main
// hits log.Fatal — there is no safe partial state.
//
//  1. Verify and load the kernel modules the host firewall needs.
//  2. Install the bridge-family nftables backstop. Pot frames that
//     somehow bypass the per-NIC nwfilter end up dropped and logged
//     here, and the DropWatcher picks the logs up to rebuild the pot.
//  3. Install the per-NIC libvirt nwfilter — the primary egress
//     control. The host firewall is its defence-in-depth backstop.
func (s *Scheduler) Bootstrap() error {
	if err := VerifyHostFirewallPrereqs(); err != nil {
		return fmt.Errorf("potscheduler: host firewall prereqs: %w", err)
	}
	if err := EnsureHostFirewall(); err != nil {
		return fmt.Errorf("potscheduler: install host firewall: %w", err)
	}
	if err := s.domains.DefineNWFilter(PotFilterXML()); err != nil {
		return fmt.Errorf("potscheduler: install nwfilter: %w", err)
	}
	return nil
}

func (s *Scheduler) Start() {
	s.watchdog.Start(context.Background(), s.queries.ListPots)
	s.dropWatcher.Start(context.Background())
	go s.reconcileLoop()
}

func (s *Scheduler) reconcileLoop() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := s.Reconcile(context.Background()); err != nil {
				log.Printf("potscheduler: %v", err)
			}
		case <-s.done:
			return
		}
	}
}

func (s *Scheduler) Stop() {
	s.dropWatcher.Stop()
	s.watchdog.Stop()
	close(s.done)
}

// rebuildBreached tears a pot down after a containment-breach signal.
// The reconcile loop will spin up a fresh replica on its next tick.
func (s *Scheduler) rebuildBreached(ctx context.Context, pot db.Pot) error {
	return s.deprovisionPot(ctx, pot)
}

// Reconcile makes one pass over every deployment and reaps expired
// pots along the way.
func (s *Scheduler) Reconcile(ctx context.Context) error {
	s.reapExpiredPots(ctx)

	deployments, err := s.queries.ListDeployments(ctx)
	if err != nil {
		return fmt.Errorf("list deployments: %w", err)
	}
	for _, deployment := range deployments {
		if err := s.reconcileDeployment(ctx, deployment); err != nil {
			log.Printf("potscheduler: deployment %s: %v", deployment.ID, err)
		}
	}
	s.updateHealthStatuses(ctx)
	return nil
}

func (s *Scheduler) reapExpiredPots(ctx context.Context) {
	expired, err := s.queries.ListExpiredPots(ctx)
	if err != nil {
		log.Printf("potscheduler: list expired: %v", err)
		return
	}
	for _, pot := range expired {
		log.Printf("potscheduler: TTL expired: %s", pot.ID)
		if err := s.deprovisionPot(ctx, pot); err != nil {
			log.Printf("potscheduler: reap %s: %v", pot.ID, err)
		}
	}
}

func (s *Scheduler) reconcileDeployment(ctx context.Context, deployment db.Deployment) error {
	current, err := s.queries.ListPotsByDeployment(ctx, deployment.ID)
	if err != nil {
		return err
	}

	// Inactive deployments are torn down entirely.
	if !deployment.Active {
		for _, pot := range current {
			if err := s.deprovisionPot(ctx, pot); err != nil {
				log.Printf("potscheduler: deprovision %s: %v", pot.ID, err)
			}
		}
		return nil
	}

	desired := int(deployment.Count)
	have := len(current)

	// Scale up.
	for replica := have; replica < desired; replica++ {
		if err := s.provisionPot(ctx, deployment, replica); err != nil {
			log.Printf("potscheduler: provision pot for %s: %v", deployment.ID, err)
		}
	}

	// Scale down (drop the tail).
	for _, pot := range current[min(desired, have):] {
		if err := s.deprovisionPot(ctx, pot); err != nil {
			log.Printf("potscheduler: deprovision %s: %v", pot.ID, err)
		}
	}
	return nil
}

func (s *Scheduler) provisionPot(ctx context.Context, deployment db.Deployment, replica int) error {
	if len(deployment.ImageIds) == 0 || len(deployment.NetworkIds) == 0 {
		return fmt.Errorf("deployment %s: no images or networks configured", deployment.ID)
	}

	// Round-robin across the deployment's images and networks so each
	// replica has a deterministic (image, network) pair.
	imageID := deployment.ImageIds[replica%len(deployment.ImageIds)]
	networkID := deployment.NetworkIds[replica%len(deployment.NetworkIds)]

	image, err := s.queries.GetImage(ctx, imageID)
	if err != nil {
		return fmt.Errorf("image %s: %w", imageID, err)
	}
	network, err := s.queries.GetNetwork(ctx, networkID)
	if err != nil {
		return fmt.Errorf("network %s: %w", networkID, err)
	}
	if network.Subnet == "" {
		return fmt.Errorf("network %s: no subnet configured", networkID)
	}

	ip, err := s.networks.AllocateIP(deployment.Ipam, network.Subnet)
	if err != nil {
		return fmt.Errorf("IPAM: %w", err)
	}

	discriminator, err := s.queries.MaxDiscriminator(ctx, db.MaxDiscriminatorParams{
		DeploymentID: deployment.ID,
		NetworkID:    networkID,
		ImageID:      imageID,
	})
	if err != nil {
		return fmt.Errorf("discriminator: %w", err)
	}
	discriminator++

	potID := db.PotID(deployment.ID, networkID, imageID, int(discriminator))
	domainName := SafeName(potID)
	sockDir := filepath.Join(s.runDir, "pots", domainName)
	socketPath := filepath.Join(sockDir, "serial.sock")
	diskPath := filepath.Join(sockDir, "disk.qcow2")

	// All on-disk artefacts go up before we touch libvirt, so the
	// rollback paths below only have to undo what they themselves set
	// up. The pot directory and disk are shared with QEMU — see
	// prepareSharedDir/prepareSharedFile for the gid story.
	if err := prepareSharedDir(filepath.Join(s.runDir, "pots")); err != nil {
		return fmt.Errorf("prepare pots dir: %w", err)
	}
	if err := prepareSharedDir(sockDir); err != nil {
		return fmt.Errorf("prepare %s: %w", sockDir, err)
	}
	if err := CloneDisk(s.networks.BaseImagePath(imageID), diskPath); err != nil {
		_ = os.RemoveAll(sockDir)
		return fmt.Errorf("clone disk: %w", err)
	}
	if err := prepareSharedFile(diskPath); err != nil {
		_ = os.RemoveAll(sockDir)
		return fmt.Errorf("prepare disk: %w", err)
	}

	mac, err := RandomMAC()
	if err != nil {
		return err
	}
	uuid, err := RandomUUID()
	if err != nil {
		return err
	}

	identity := newIdentity(deployment.ID, discriminator, image)
	credHint := fmt.Sprintf("%s@%s", identity.Hostname, identity.AdminUser)

	var expiresAt *time.Time
	if deployment.TtlMinutes > 0 {
		expiry := time.Now().Add(time.Duration(deployment.TtlMinutes) * time.Minute)
		expiresAt = &expiry
	}

	// Bridge for this network — idempotent, so calling it on every pot
	// is cheap.
	bridge, err := s.networks.ProvisionNetwork(network.ID, network.InterfaceID, network.Type, network.VlanID)
	if err != nil {
		_ = os.RemoveAll(sockDir)
		return fmt.Errorf("provision bridge for %s: %w", network.ID, err)
	}

	domainXML, err := RenderDomainXML(DomainXMLParams{
		Name:       domainName,
		UUID:       uuid,
		DiskPath:   diskPath,
		MAC:        mac,
		Bridge:     bridge,
		SocketPath: socketPath,
		FilterName: PotFilterName,
	})
	if err != nil {
		return fmt.Errorf("render XML: %w", err)
	}

	pot, err := s.queries.CreatePot(ctx, db.CreatePotParams{
		ID:            potID,
		DeploymentID:  deployment.ID,
		ImageID:       imageID,
		NetworkID:     networkID,
		Discriminator: discriminator,
		Status:        "degraded",
		Ip:            ip,
		ExpiresAt:     expiresAt,
		CredHint:      credHint,
		Mac:           mac,
	})
	if err != nil {
		_ = os.RemoveAll(sockDir)
		return fmt.Errorf("db.CreatePot: %w", err)
	}

	if err := s.domains.Define(domainXML); err != nil {
		_ = s.queries.DeletePot(ctx, pot.ID)
		_ = os.RemoveAll(sockDir)
		return fmt.Errorf("libvirt define: %w", err)
	}
	if err := s.domains.Start(domainName); err != nil {
		_ = s.domains.Undefine(domainName)
		_ = s.queries.DeletePot(ctx, pot.ID)
		_ = os.RemoveAll(sockDir)
		return fmt.Errorf("libvirt start: %w", err)
	}

	if err := s.pots.Connect(potID, socketPath, featuresFromImage(image), identity); err != nil {
		log.Printf("potscheduler: potmgr connect %s: %v (will retry)", potID, err)
	}

	s.watchdog.Track(potID)

	log.Printf("potscheduler: provisioned %s at %s (hostname=%s ttl=%dm)",
		potID, ip, identity.Hostname, deployment.TtlMinutes)
	return nil
}

func (s *Scheduler) deprovisionPot(ctx context.Context, pot db.Pot) error {
	s.watchdog.Forget(pot.ID)
	s.pots.Disconnect(pot.ID)

	domainName := SafeName(pot.ID)
	_ = s.domains.Stop(domainName)

	// Destroy + Undefine remove the live and persistent definitions.
	// If the domain is already gone (e.g. a previous run was interrupted
	// mid-deprovision), treat that as success and continue cleanup.
	if err := s.domains.Destroy(domainName); err != nil {
		exists, _ := s.domains.Exists(domainName)
		if exists {
			return fmt.Errorf("libvirt destroy %s: %w", domainName, err)
		}
	} else if err := s.domains.Undefine(domainName); err != nil {
		return fmt.Errorf("libvirt undefine %s: %w", domainName, err)
	}

	sockDir := filepath.Join(s.runDir, "pots", domainName)
	_ = os.RemoveAll(sockDir)

	if err := s.queries.DeletePot(ctx, pot.ID); err != nil {
		return fmt.Errorf("db.DeletePot: %w", err)
	}
	log.Printf("potscheduler: deprovisioned %s", pot.ID)
	return nil
}

// updateHealthStatuses writes a "healthy" or "degraded" status to every
// pot row, depending on whether the agent connection is up.
func (s *Scheduler) updateHealthStatuses(ctx context.Context) {
	pots, err := s.queries.ListPots(ctx)
	if err != nil {
		log.Printf("potscheduler: list pots: %v", err)
		return
	}
	for _, pot := range pots {
		status := "degraded"
		if s.pots.IsHealthy(pot.ID) {
			status = "healthy"
		}
		err := s.queries.UpdatePotStatus(ctx, db.UpdatePotStatusParams{
			ID:     pot.ID,
			Status: status,
		})
		if err != nil {
			log.Printf("potscheduler: update status %s: %v", pot.ID, err)
		}
	}
}

func featuresFromImage(image db.Image) []potmgr.Feature {
	var parsed []db.ImageFeature
	_ = json.Unmarshal(image.Features, &parsed)

	out := make([]potmgr.Feature, len(parsed))
	for i, f := range parsed {
		out[i] = potmgr.Feature{Name: f.Name}
	}
	return out
}

// newIdentity returns a fresh per-pot identity: unique hostname,
// machine-id, and admin credential. The credential is ephemeral — it
// only ever lives in the agent config in RAM. The DB stores a hint
// (user@host), never the password.
//
// Varying these per pot avoids the "one image cloned many times"
// fingerprint problem: without it, every pot in a deployment would be
// trivially correlatable.
func newIdentity(deploymentID string, discriminator int32, image db.Image) potmgr.Identity {
	hostname := fmt.Sprintf("%s-%s-%02d",
		sanitizeHost(image.Base), sanitizeHost(deploymentID), discriminator)
	return potmgr.Identity{
		Hostname:  hostname,
		MachineID: randomHex(16),
		AdminUser: randomUser(),
		AdminPass: randomHex(12),
	}
}

// sanitizeHost reduces an arbitrary string to a libvirt/DNS-safe host
// fragment. Lowercase alphanumerics are kept verbatim; "-_." collapse
// to '-'; everything else is dropped. Empty results fall back to "pot"
// so the calling template never produces "--01".
func sanitizeHost(name string) string {
	name = strings.ToLower(name)

	var out strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			out.WriteRune('-')
		}
	}
	if out.Len() == 0 {
		return "pot"
	}
	return out.String()
}

func randomHex(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

var adminUserPool = []string{
	"admin", "root", "ubuntu", "ec2-user", "operator", "svc_backup",
	"jenkins", "deploy", "support", "oracle",
}

func randomUser() string {
	var index [1]byte
	_, _ = rand.Read(index[:])
	return adminUserPool[int(index[0])%len(adminUserPool)]
}
