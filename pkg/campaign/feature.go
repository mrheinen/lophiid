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

import "time"

// FeatureSet holds the enriched feature values for a single request.
// Keys are feature names (e.g. "source_ip", "cmp_hash", "asn").
// Values are the feature values as strings. Features with empty values are
// omitted and do not participate in similarity scoring.
type FeatureSet map[string]string

// Set adds a feature value if non-empty.
func (fs FeatureSet) Set(key, value string) {
	if value != "" {
		fs[key] = value
	}
}

// Get returns the value for a feature, or empty string if absent.
func (fs FeatureSet) Get(key string) string {
	return fs[key]
}

// Has returns whether the feature is present and non-empty.
func (fs FeatureSet) Has(key string) bool {
	v, ok := fs[key]
	return ok && v != ""
}

// Merge copies all features from other into fs. Existing keys are overwritten.
func (fs FeatureSet) Merge(other FeatureSet) {
	for k, v := range other {
		fs[k] = v
	}
}

// NewFeatureSet creates an empty FeatureSet.
func NewFeatureSet() FeatureSet {
	return make(FeatureSet)
}

// EnrichedRequest wraps a request ID with its enriched feature set.
type EnrichedRequest struct {
	RequestID    int64
	SourceIP     string
	SessionID    int64
	TimeReceived time.Time
	Features     FeatureSet
}
