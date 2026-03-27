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
	"github.com/stretchr/testify/require"
)

func TestFingerprint_AddAndHas(t *testing.T) {
	fp := NewFingerprint()
	fp.Add("source_ip", "1.2.3.4")
	fp.Add("source_ip", "5.6.7.8")
	fp.Add("cmp_hash", "abc123")

	assert.True(t, fp.Has("source_ip", "1.2.3.4"))
	assert.True(t, fp.Has("source_ip", "5.6.7.8"))
	assert.True(t, fp.Has("cmp_hash", "abc123"))
	assert.False(t, fp.Has("source_ip", "9.9.9.9"))
	assert.False(t, fp.Has("missing_key", "value"))
}

func TestFingerprint_AddIgnoresEmpty(t *testing.T) {
	fp := NewFingerprint()
	fp.Add("key", "")
	assert.False(t, fp.Has("key", ""))
	assert.Equal(t, 0, len(fp))
}

func TestFingerprint_HasReturnsFalseForEmpty(t *testing.T) {
	fp := NewFingerprint()
	fp.Add("key", "val")
	assert.False(t, fp.Has("key", ""))
}

func TestFingerprint_JSONRoundTrip(t *testing.T) {
	fp := NewFingerprint()
	fp.Add("source_ip", "1.2.3.4")
	fp.Add("source_ip", "5.6.7.8")
	fp.Add("cmp_hash", "abc123")

	jsonStr, err := fp.ToJSON()
	require.NoError(t, err)

	restored, err := FingerprintFromJSON(jsonStr)
	require.NoError(t, err)

	assert.True(t, restored.Has("source_ip", "1.2.3.4"))
	assert.True(t, restored.Has("source_ip", "5.6.7.8"))
	assert.True(t, restored.Has("cmp_hash", "abc123"))
	assert.False(t, restored.Has("source_ip", "9.9.9.9"))
}

func TestFingerprint_JSONDeterministic(t *testing.T) {
	fp := NewFingerprint()
	fp.Add("b_key", "2")
	fp.Add("a_key", "1")
	fp.Add("b_key", "1")

	json1, err := fp.ToJSON()
	require.NoError(t, err)
	json2, err := fp.ToJSON()
	require.NoError(t, err)

	assert.Equal(t, json1, json2, "JSON serialization should be deterministic")
}

func TestFingerprintFromJSON_EmptyInputs(t *testing.T) {
	fp, err := FingerprintFromJSON("")
	require.NoError(t, err)
	assert.Equal(t, 0, len(fp))

	fp, err = FingerprintFromJSON("{}")
	require.NoError(t, err)
	assert.Equal(t, 0, len(fp))
}

func TestFingerprintFromJSON_InvalidJSON(t *testing.T) {
	_, err := FingerprintFromJSON("not json")
	assert.Error(t, err)
}

func TestCreateFromFeatureSets(t *testing.T) {
	fs1 := NewFeatureSet()
	fs1.Set("source_ip", "1.2.3.4")
	fs1.Set("cmp_hash", "abc")

	fs2 := NewFeatureSet()
	fs2.Set("source_ip", "5.6.7.8")
	fs2.Set("cmp_hash", "abc")
	fs2.Set("uri", "/test")

	fp := CreateFromFeatureSets([]FeatureSet{fs1, fs2})

	assert.True(t, fp.Has("source_ip", "1.2.3.4"))
	assert.True(t, fp.Has("source_ip", "5.6.7.8"))
	assert.True(t, fp.Has("cmp_hash", "abc"))
	assert.True(t, fp.Has("uri", "/test"))
}

func TestFingerprint_Expand(t *testing.T) {
	fp := NewFingerprint()
	fp.Add("source_ip", "1.2.3.4")

	fs := NewFeatureSet()
	fs.Set("source_ip", "1.2.3.4") // Already present.
	fs.Set("source_ip", "5.6.7.8") // FeatureSet only holds one value per key.
	fs.Set("cmp_hash", "new_hash")

	expanded := fp.Expand(fs, ExhaustMap{})
	assert.True(t, expanded)
	assert.True(t, fp.Has("cmp_hash", "new_hash"))
}

func TestFingerprint_ExpandNoChange(t *testing.T) {
	fp := NewFingerprint()
	fp.Add("source_ip", "1.2.3.4")

	fs := NewFeatureSet()
	fs.Set("source_ip", "1.2.3.4")

	expanded := fp.Expand(fs, ExhaustMap{})
	assert.False(t, expanded, "should not report expansion when nothing new")
}

func TestFingerprint_ExpandStopsAtExhaustNumber(t *testing.T) {
	fp := NewFingerprint()
	fp.Add("source_ip", "1.2.3.4")
	fp.Add("source_ip", "5.6.7.8")

	// exhaust_number=2 means the feature is already full.
	exhaust := ExhaustMap{"source_ip": 2}

	fs := NewFeatureSet()
	fs.Set("source_ip", "9.9.9.9")

	expanded := fp.Expand(fs, exhaust)
	assert.False(t, expanded, "exhausted feature should not accept new values")
	assert.False(t, fp.Has("source_ip", "9.9.9.9"))
	assert.Equal(t, 2, len(fp["source_ip"]), "cardinality must stay capped")
}

func TestFingerprint_ExpandNonExhaustedFeatureStillAdded(t *testing.T) {
	fp := NewFingerprint()
	fp.Add("source_ip", "1.2.3.4")

	// exhaust_number=5 but only 1 value present — not exhausted.
	exhaust := ExhaustMap{"source_ip": 5}

	fs := NewFeatureSet()
	fs.Set("source_ip", "2.2.2.2")

	expanded := fp.Expand(fs, exhaust)
	assert.True(t, expanded)
	assert.True(t, fp.Has("source_ip", "2.2.2.2"))
}

func TestFingerprint_Union(t *testing.T) {
	fp1 := NewFingerprint()
	fp1.Add("source_ip", "1.2.3.4")
	fp1.Add("cmp_hash", "abc")

	fp2 := NewFingerprint()
	fp2.Add("source_ip", "5.6.7.8")
	fp2.Add("uri", "/test")

	expanded := fp1.Union(fp2, ExhaustMap{})
	assert.True(t, expanded)
	assert.True(t, fp1.Has("source_ip", "1.2.3.4"))
	assert.True(t, fp1.Has("source_ip", "5.6.7.8"))
	assert.True(t, fp1.Has("cmp_hash", "abc"))
	assert.True(t, fp1.Has("uri", "/test"))
}

func TestFingerprint_UnionNoChange(t *testing.T) {
	fp1 := NewFingerprint()
	fp1.Add("source_ip", "1.2.3.4")

	fp2 := NewFingerprint()
	fp2.Add("source_ip", "1.2.3.4")

	expanded := fp1.Union(fp2, ExhaustMap{})
	assert.False(t, expanded)
}

func TestFingerprint_UnionStopsAtExhaustNumber(t *testing.T) {
	fp1 := NewFingerprint()
	fp1.Add("source_ip", "1.2.3.4")
	fp1.Add("source_ip", "5.6.7.8")

	fp2 := NewFingerprint()
	fp2.Add("source_ip", "9.9.9.9")
	fp2.Add("source_ip", "10.0.0.1")

	// exhaust_number=2 means fp1's source_ip is already full.
	exhaust := ExhaustMap{"source_ip": 2}

	expanded := fp1.Union(fp2, exhaust)
	assert.False(t, expanded, "exhausted feature should block all new values from union")
	assert.Equal(t, 2, len(fp1["source_ip"]), "cardinality must stay capped")
	assert.False(t, fp1.Has("source_ip", "9.9.9.9"))
}
