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
package util

import (
	"fmt"

	"github.com/blang/semver/v4"
)

// IsLophiidVersionCompatible checks if two versions are compatible by making
// sure the major and minor version are the same.
func IsLophiidVersionCompatible(vOne string, vTwo string) error {
	v1, err := semver.Make(vOne)
	if err != nil {
		return fmt.Errorf("unable to parse version %s: %w", vOne, err)
	}

	v2, err := semver.Make(vTwo)
	if err != nil {
		return fmt.Errorf("unable to parse version %s: %w", vOne, err)
	}

	if v1.Major != v2.Major || v1.Minor != v2.Minor {
		return fmt.Errorf("incompatible version: %s and %s", vOne, vTwo)
	}

	return nil
}
