package util

import (
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// DropPrivilegesAndChroot changes the user and group ID of the current process.
// This needs to be called after the HTTP servers are up and running.
func DropPrivilegesAndChroot(username, chrootDir string) error {
	_, err := os.Stat(chrootDir)
	if err != nil {
		return fmt.Errorf("could not stat chroot directory: %w", err)
	}

	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("could not lookup user: %w", err)
	}

	intUid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("invalid uid: %s", u.Uid)
	}

	intGid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("invalid uid: %s", u.Gid)
	}

	if err := syscall.Chroot(chrootDir); err != nil {
		return fmt.Errorf("could not chroot: %w", err)
	}

	if err := syscall.Chdir("/"); err != nil {
		return fmt.Errorf("could not chdir: %w", err)
	}

	if err := syscall.Setgid(intGid); err != nil {
		return fmt.Errorf("could not change group ID: %w", err)
	}
	if err := syscall.Setuid(intUid); err != nil {
		return fmt.Errorf("could not change user ID: %w", err)
	}

	slog.Info("Dropped privileges and chrooted", slog.String("chroot", chrootDir))
	return nil
}
