// Lophiid distributed honeypot
// Copyright (C) 2026 Niels Heinen
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
package api

import (
	"lophiid/pkg/database"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetURIStatistics_InvalidLookupTypeRejected(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{}

	for _, badType := range []string{
		"source_ip",
		"1; DROP TABLE request; --",
		"uri OR 1=1",
		"",
		"URI",
	} {
		_, err := GetURIStatistics(fakeDB, badType, "somevalue", "")
		assert.Errorf(t, err, "expected error for lookup_type %q", badType)
	}
}

func TestGetURIStatistics_ValidLookupTypesAccepted(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{}

	for _, validType := range []string{"uri", "cmp_hash", "base_hash"} {
		_, err := GetURIStatistics(fakeDB, validType, "somevalue", "")
		require.NoErrorf(t, err, "unexpected error for valid lookup_type %q", validType)
	}
}

func TestGetURIStatistics_ColumnNameComesFromMap(t *testing.T) {
	for input, expected := range validLookupColumns {
		assert.Equalf(t, input, expected, "map value for %q should equal the key (trusted SQL identifier)", input)
	}
}
