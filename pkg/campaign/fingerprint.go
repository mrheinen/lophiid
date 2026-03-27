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
	"encoding/json"
	"fmt"
	"sort"
)

// Fingerprint represents a campaign's identity as a set of observed feature
// values per feature key. For example: {"source_ip": {"1.2.3.4", "5.6.7.8"},
// "cmp_hash": {"abc123"}}. A request matches a fingerprint if any of its
// feature values exist in the fingerprint's value set for that feature.
type Fingerprint map[string]map[string]bool

// NewFingerprint creates an empty Fingerprint.
func NewFingerprint() Fingerprint {
	return make(Fingerprint)
}

// FingerprintFromJSON deserializes a fingerprint from its JSON representation.
func FingerprintFromJSON(data string) (Fingerprint, error) {
	if data == "" || data == "{}" {
		return NewFingerprint(), nil
	}
	// JSON representation uses arrays for compactness.
	var raw map[string][]string
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return nil, fmt.Errorf("parsing fingerprint JSON: %w", err)
	}
	fp := NewFingerprint()
	for key, values := range raw {
		fp[key] = make(map[string]bool, len(values))
		for _, v := range values {
			fp[key][v] = true
		}
	}
	return fp, nil
}

// ToJSON serializes the fingerprint to a deterministic JSON string.
func (fp Fingerprint) ToJSON() (string, error) {
	raw := make(map[string][]string, len(fp))
	for key, valSet := range fp {
		vals := make([]string, 0, len(valSet))
		for v := range valSet {
			vals = append(vals, v)
		}
		sort.Strings(vals)
		raw[key] = vals
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("marshaling fingerprint: %w", err)
	}
	return string(data), nil
}

// Add adds a single feature value to the fingerprint.
func (fp Fingerprint) Add(key, value string) {
	if value == "" {
		return
	}
	if fp[key] == nil {
		fp[key] = make(map[string]bool)
	}
	fp[key][value] = true
}

// Has returns whether the fingerprint contains the given value for the given feature.
func (fp Fingerprint) Has(key, value string) bool {
	if value == "" {
		return false
	}
	valSet, ok := fp[key]
	if !ok {
		return false
	}
	return valSet[value]
}

// CreateFromFeatureSets creates a new fingerprint from a slice of feature sets.
// All non-empty feature values from all feature sets are included.
func CreateFromFeatureSets(featureSets []FeatureSet) Fingerprint {
	fp := NewFingerprint()
	for _, fs := range featureSets {
		for key, value := range fs {
			fp.Add(key, value)
		}
	}
	return fp
}

// Expand adds new feature values from a feature set to the fingerprint.
// Values for features whose cardinality already meets or exceeds their
// exhaust_number in the ExhaustMap are not added.
// Returns true if the fingerprint was actually expanded.
func (fp Fingerprint) Expand(fs FeatureSet, exhaust ExhaustMap) bool {
	expanded := false
	for key, value := range fs {
		if value == "" {
			continue
		}
		if exhaustNum, ok := exhaust[key]; ok && len(fp[key]) >= exhaustNum {
			continue
		}
		if !fp.Has(key, value) {
			fp.Add(key, value)
			expanded = true
		}
	}
	return expanded
}

// Union merges another fingerprint into this one.
// Values for features whose cardinality already meets or exceeds their
// exhaust_number in the ExhaustMap are not added.
// Returns true if this fingerprint was actually expanded.
func (fp Fingerprint) Union(other Fingerprint, exhaust ExhaustMap) bool {
	expanded := false
	for key, valSet := range other {
		if fp[key] == nil {
			fp[key] = make(map[string]bool)
		}
		for v := range valSet {
			if exhaustNum, ok := exhaust[key]; ok && len(fp[key]) >= exhaustNum {
				break
			}
			if !fp[key][v] {
				fp[key][v] = true
				expanded = true
			}
		}
	}
	return expanded
}
