// Lophiid distributed honeypot
// Copyright (C) 2024 Niels Heinen
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
//
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
