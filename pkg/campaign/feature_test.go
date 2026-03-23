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
package campaign

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFeatureSet_SetAndGet(t *testing.T) {
	fs := NewFeatureSet()
	fs.Set("source_ip", "1.2.3.4")
	fs.Set("empty", "")

	assert.Equal(t, "1.2.3.4", fs.Get("source_ip"))
	assert.Equal(t, "", fs.Get("empty"), "empty values should not be stored")
	assert.Equal(t, "", fs.Get("missing"), "missing keys return empty string")
}

func TestFeatureSet_Has(t *testing.T) {
	fs := NewFeatureSet()
	fs.Set("source_ip", "1.2.3.4")

	assert.True(t, fs.Has("source_ip"))
	assert.False(t, fs.Has("missing"))
}

func TestFeatureSet_Merge(t *testing.T) {
	a := NewFeatureSet()
	a.Set("source_ip", "1.2.3.4")
	a.Set("method", "GET")

	b := NewFeatureSet()
	b.Set("source_ip", "5.6.7.8")
	b.Set("uri", "/test")

	a.Merge(b)

	assert.Equal(t, "5.6.7.8", a.Get("source_ip"), "merge overwrites existing keys")
	assert.Equal(t, "GET", a.Get("method"), "merge preserves non-conflicting keys")
	assert.Equal(t, "/test", a.Get("uri"), "merge adds new keys")
}

func TestFeatureSet_SetIgnoresEmpty(t *testing.T) {
	fs := NewFeatureSet()
	fs.Set("key", "")
	assert.False(t, fs.Has("key"))
	assert.Equal(t, 0, len(fs))
}
