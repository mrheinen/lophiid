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

	"lophiid/pkg/util/constants"

	"github.com/stretchr/testify/assert"
)

func TestBuildWeightMap(t *testing.T) {
	sources := map[string]SourceConfig{
		constants.CampaignSourceRequest: {
			Enabled: true,
			Features: map[string]FeatureConfig{
				"source_ip": {Weight: 0.9, ExhaustNumber: 5000},
				"cmp_hash":  {Weight: 0.8},
			},
		},
		constants.CampaignSourceWhois: {
			Enabled: true,
			Features: map[string]FeatureConfig{
				"geoip_asn":     {Weight: 0.3},
				"geoip_asn_org": {Weight: 0.5, ExhaustNumber: 200},
				"geoip_country": {Weight: 0.2},
			},
		},
		constants.CampaignSourceP0f: {
			Enabled: false,
			Features: map[string]FeatureConfig{
				"os_name": {Weight: 0.2},
			},
		},
	}

	wm := BuildWeightMap(sources)

	assert.Equal(t, 0.9, wm["source_ip"])
	assert.Equal(t, 0.8, wm["cmp_hash"])
	assert.Equal(t, 0.3, wm["geoip_asn"])
	assert.Equal(t, 0.5, wm["geoip_asn_org"])
	assert.Equal(t, 0.2, wm["geoip_country"])
	assert.Equal(t, 0.0, wm["os_name"], "disabled source features should not be in weight map")
}

func TestBuildExhaustMap(t *testing.T) {
	sources := map[string]SourceConfig{
		constants.CampaignSourceRequest: {
			Enabled: true,
			Features: map[string]FeatureConfig{
				"source_ip": {Weight: 0.9, ExhaustNumber: 5000},
				"cmp_hash":  {Weight: 0.8},
			},
		},
		constants.CampaignSourceWhois: {
			Enabled: true,
			Features: map[string]FeatureConfig{
				"geoip_asn_org": {Weight: 0.5, ExhaustNumber: 200},
			},
		},
		constants.CampaignSourceP0f: {
			Enabled: false,
			Features: map[string]FeatureConfig{
				"os_name": {Weight: 0.2, ExhaustNumber: 10},
			},
		},
	}

	em := BuildExhaustMap(sources)

	assert.Equal(t, 5000, em["source_ip"])
	assert.Equal(t, 200, em["geoip_asn_org"])
	_, hasCmpHash := em["cmp_hash"]
	assert.False(t, hasCmpHash, "feature with exhaust_number=0 should not be in exhaust map")
	_, hasOsName := em["os_name"]
	assert.False(t, hasOsName, "disabled source features should not be in exhaust map")
}

func TestScoreFeatureSets_FullMatch(t *testing.T) {
	a := NewFeatureSet()
	a.Set("source_ip", "1.2.3.4")
	a.Set("cmp_hash", "abc123")

	b := NewFeatureSet()
	b.Set("source_ip", "1.2.3.4")
	b.Set("cmp_hash", "abc123")

	weights := WeightMap{
		"source_ip": 0.9,
		"cmp_hash":  0.8,
	}

	score := ScoreFeatureSets(a, b, weights)
	assert.InDelta(t, 1.7, score, 0.001)
}

func TestScoreFeatureSets_PartialMatch(t *testing.T) {
	a := NewFeatureSet()
	a.Set("source_ip", "1.2.3.4")
	a.Set("cmp_hash", "abc123")

	b := NewFeatureSet()
	b.Set("source_ip", "1.2.3.4")
	b.Set("cmp_hash", "different")

	weights := WeightMap{
		"source_ip": 0.9,
		"cmp_hash":  0.8,
	}

	score := ScoreFeatureSets(a, b, weights)
	assert.InDelta(t, 0.9, score, 0.001)
}

func TestScoreFeatureSets_NoMatch(t *testing.T) {
	a := NewFeatureSet()
	a.Set("source_ip", "1.2.3.4")

	b := NewFeatureSet()
	b.Set("source_ip", "5.6.7.8")

	weights := WeightMap{
		"source_ip": 0.9,
	}

	score := ScoreFeatureSets(a, b, weights)
	assert.Equal(t, 0.0, score)
}

func TestScoreFeatureSets_ZeroWeightIgnored(t *testing.T) {
	a := NewFeatureSet()
	a.Set("ai_cve", "CVE-2024-1234")

	b := NewFeatureSet()
	b.Set("ai_cve", "CVE-2024-1234")

	weights := WeightMap{
		"ai_cve": 0.0,
	}

	score := ScoreFeatureSets(a, b, weights)
	assert.Equal(t, 0.0, score, "zero-weight features should not contribute")
}

func TestScoreFeatureSets_MissingFeatureIgnored(t *testing.T) {
	a := NewFeatureSet()
	a.Set("source_ip", "1.2.3.4")

	b := NewFeatureSet()
	// source_ip absent in b.

	weights := WeightMap{
		"source_ip": 0.9,
	}

	score := ScoreFeatureSets(a, b, weights)
	assert.Equal(t, 0.0, score)
}

func TestScoreAgainstFingerprint_MatchesValue(t *testing.T) {
	fs := NewFeatureSet()
	fs.Set("source_ip", "1.2.3.4")
	fs.Set("cmp_hash", "abc123")

	fp := NewFingerprint()
	fp.Add("source_ip", "1.2.3.4")
	fp.Add("source_ip", "5.6.7.8")
	fp.Add("cmp_hash", "abc123")
	fp.Add("cmp_hash", "def456")

	weights := WeightMap{
		"source_ip": 0.9,
		"cmp_hash":  0.8,
	}

	score := ScoreAgainstFingerprint(fs, fp, weights, ExhaustMap{})
	assert.InDelta(t, 1.7, score, 0.001)
}

func TestScoreAgainstFingerprint_NoMatch(t *testing.T) {
	fs := NewFeatureSet()
	fs.Set("source_ip", "9.9.9.9")

	fp := NewFingerprint()
	fp.Add("source_ip", "1.2.3.4")

	weights := WeightMap{
		"source_ip": 0.9,
	}

	score := ScoreAgainstFingerprint(fs, fp, weights, ExhaustMap{})
	assert.Equal(t, 0.0, score)
}

func TestScoreAgainstFingerprint_EmptyFingerprint(t *testing.T) {
	fs := NewFeatureSet()
	fs.Set("source_ip", "1.2.3.4")

	fp := NewFingerprint()

	weights := WeightMap{
		"source_ip": 0.9,
	}

	score := ScoreAgainstFingerprint(fs, fp, weights, ExhaustMap{})
	assert.Equal(t, 0.0, score)
}

func TestScoreAgainstFingerprint_ExhaustedFeatureSkipped(t *testing.T) {
	fs := NewFeatureSet()
	fs.Set("source_ip", "1.2.3.4")
	fs.Set("cmp_hash", "abc123")

	fp := NewFingerprint()
	// Populate source_ip beyond the exhaust_number of 3.
	fp.Add("source_ip", "1.2.3.4")
	fp.Add("source_ip", "5.6.7.8")
	fp.Add("source_ip", "9.9.9.9")
	fp.Add("cmp_hash", "abc123")

	weights := WeightMap{
		"source_ip": 0.9,
		"cmp_hash":  0.8,
	}
	exhaust := ExhaustMap{"source_ip": 3}

	// source_ip has 3 values == exhaust_number 3, so it is skipped.
	// Only cmp_hash contributes.
	score := ScoreAgainstFingerprint(fs, fp, weights, exhaust)
	assert.InDelta(t, 0.8, score, 0.001, "exhausted feature should not contribute to score")
}

func TestScoreAgainstFingerprint_UnexhaustedFeatureStillScores(t *testing.T) {
	fs := NewFeatureSet()
	fs.Set("source_ip", "1.2.3.4")

	fp := NewFingerprint()
	fp.Add("source_ip", "1.2.3.4")
	fp.Add("source_ip", "5.6.7.8")

	weights := WeightMap{"source_ip": 0.9}
	// exhaust_number is 5 but fingerprint only has 2 values — not exhausted.
	exhaust := ExhaustMap{"source_ip": 5}

	score := ScoreAgainstFingerprint(fs, fp, weights, exhaust)
	assert.InDelta(t, 0.9, score, 0.001, "non-exhausted feature should still contribute")
}
