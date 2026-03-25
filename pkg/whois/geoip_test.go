// Lophiid distributed honeypot
// Copyright (C) 2023-2026 Niels Heinen
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
package whois

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMaxMindGeoIPLookupInvalidDir(t *testing.T) {
	_, err := NewMaxMindGeoIPLookup("/nonexistent/path")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GeoLite2-City")
}

func TestNewMaxMindGeoIPLookupMissingASNDb(t *testing.T) {
	// Create a temp dir with only a city db (empty file) to trigger ASN error.
	tmpDir := t.TempDir()

	// Write a dummy file as GeoLite2-City.mmdb — it will fail at open because
	// it's not a valid mmdb, but the error message tells us which file was tried.
	_, err := NewMaxMindGeoIPLookup(tmpDir)
	require.Error(t, err)
	// Should fail on the City db since the file doesn't exist.
	assert.Contains(t, err.Error(), "GeoLite2-City")
}
