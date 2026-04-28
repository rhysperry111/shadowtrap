package services

import (
	"log"
	"os"
	"os/exec"
)

// applyHostname sets the runtime hostname and updates /etc/hostname so
// sshd banners and similar surfaces show a per-pot name. Failures are
// logged but not fatal — hostname is realism, not containment.
func applyHostname(name string) {
	if err := exec.Command("hostname", name).Run(); err != nil {
		log.Printf("identity: set runtime hostname: %v", err)
	}
	if err := os.WriteFile("/etc/hostname", []byte(name+"\n"), 0o644); err != nil {
		log.Printf("identity: write /etc/hostname: %v", err)
	}
}

// applyMachineID writes a per-pot /etc/machine-id. systemd, D-Bus, and
// many daemons key identity off this; if every pot has the same one,
// they all look like the same host on the network.
func applyMachineID(id string) {
	if err := os.WriteFile("/etc/machine-id", []byte(id+"\n"), 0o444); err != nil {
		log.Printf("identity: write /etc/machine-id: %v", err)
	}
}
