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

// WeightMap maps feature names to their configured weights.
type WeightMap map[string]float64

// ExhaustMap maps feature names to their configured exhaust numbers.
// Only features with ExhaustNumber > 0 are present in the map; absence means
// the feature is never exhausted.
type ExhaustMap map[string]int

// BuildWeightMap flattens all source configs into a single feature->weight map.
func BuildWeightMap(sources map[string]SourceConfig) WeightMap {
	wm := make(WeightMap)
	for _, sc := range sources {
		if !sc.Enabled {
			continue
		}
		for feature, fc := range sc.Features {
			wm[feature] = fc.Weight
		}
	}
	return wm
}

// BuildExhaustMap flattens all source configs into a single feature->exhaust_number
// map. Only features with ExhaustNumber > 0 are included.
func BuildExhaustMap(sources map[string]SourceConfig) ExhaustMap {
	em := make(ExhaustMap)
	for _, sc := range sources {
		if !sc.Enabled {
			continue
		}
		for feature, fc := range sc.Features {
			if fc.ExhaustNumber > 0 {
				em[feature] = fc.ExhaustNumber
			}
		}
	}
	return em
}

// ScoreFeatureSets computes the weighted similarity score between two feature sets.
// For each feature present in both sets with the same value, the feature's weight
// is added to the score. Features not present in the weight map are ignored.
func ScoreFeatureSets(a, b FeatureSet, weights WeightMap) float64 {
	var score float64
	for feature, weight := range weights {
		if weight == 0 {
			continue
		}
		va := a.Get(feature)
		vb := b.Get(feature)
		if va != "" && va == vb {
			score += weight
		}
	}
	return score
}

// ScoreAgainstFingerprint computes the weighted similarity score between a
// feature set and a campaign fingerprint. For each feature in the feature set
// whose value exists in the fingerprint's value set, the weight is added.
// Features whose fingerprint cardinality meets or exceeds their exhaust_number
// are skipped, contributing 0 to the score.
func ScoreAgainstFingerprint(fs FeatureSet, fp Fingerprint, weights WeightMap, exhaust ExhaustMap) float64 {
	var score float64
	for feature, weight := range weights {
		if weight == 0 {
			continue
		}
		if exhaustNum, ok := exhaust[feature]; ok && len(fp[feature]) >= exhaustNum {
			continue
		}
		value := fs.Get(feature)
		if value != "" && fp.Has(feature, value) {
			score += weight
		}
	}
	return score
}
