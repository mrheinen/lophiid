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
package backend

import (
	"testing"
	"time"
)

func TestNewRuleVsContentCache(t *testing.T) {
	c := NewRuleVsContentCache(0)

	sIP := "1.1.1.1"
	rID := int64(1)
	cID := int64(10)

	c.Store(sIP, rID, cID)

	// Check if it is there.
	if !c.Has(sIP, rID, cID) {
		t.Error("cache misses our entry")
	}

	c.CleanupExpired()
	if c.Has(sIP, rID, cID) {
		t.Error("cache has our entry")
	}
}

func TestNewRuleVsContentCacheLongTimeout(t *testing.T) {
	c := NewRuleVsContentCache(time.Hour * 5)

	sIP := "1.1.1.1"
	rID := int64(1)
	cID := int64(10)

	c.Store(sIP, rID, cID)

	// Check if it is there.
	if !c.Has(sIP, rID, cID) {
		t.Error("cache misses our entry")
	}

	// Because of the long timeout this should be a noop
	c.CleanupExpired()

	if !c.Has(sIP, rID, cID) {
		t.Error("cache should have had our entry")
	}
}
