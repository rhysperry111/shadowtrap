package potscheduler

// File permissions for pot artefacts shared with libvirtd.
//
// The controller runs under the operator's user account; libvirtd's
// QEMU process runs under a separate uid (usually `qemu`, often added
// to the `libvirt` group). For QEMU to read the cloned disk and bind
// the virtio-serial socket, every artefact has to be readable and
// writable by the parent directory's group — without us hardcoding a
// group name. We do that by inheriting the parent's gid onto everything
// we create:
//
//   Directories: mode 2770. The setgid bit makes new entries inside
//                inherit the directory's gid automatically.
//   Files:       mode 0660, then chown to (controller uid, parent gid).

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const (
	sharedDirMode  os.FileMode = 0o2770
	sharedFileMode os.FileMode = 0o0660
)

// prepareSharedDir makes sure dir exists with mode 2770 and is owned
// by (current uid, parent dir's gid). Safe to call on a directory that
// already exists.
func prepareSharedDir(dir string) error {
	if err := os.MkdirAll(dir, sharedDirMode); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	// MkdirAll honours umask, which usually strips the setgid bit, so
	// re-apply the desired mode unconditionally.
	if err := os.Chmod(dir, sharedDirMode); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}

	gid, err := parentGID(dir)
	if err != nil {
		return err
	}
	if err := os.Chown(dir, os.Getuid(), gid); err != nil {
		return fmt.Errorf("chown %s: %w", dir, err)
	}
	return nil
}

// prepareSharedFile chmods path to 0660 and chowns it to (current uid,
// parent dir's gid).
func prepareSharedFile(path string) error {
	if err := os.Chmod(path, sharedFileMode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	gid, err := parentGID(path)
	if err != nil {
		return err
	}
	if err := os.Chown(path, os.Getuid(), gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}

func parentGID(path string) (int, error) {
	parent := filepath.Dir(path)

	info, err := os.Stat(parent)
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", parent, err)
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("stat %s: unsupported on this platform", parent)
	}
	return int(sys.Gid), nil
}
