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

func TestClusterUnmatched_AllSimilar(t *testing.T) {
	requests := []EnrichedRequest{
		{RequestID: 1, Features: FeatureSet{"source_ip": "1.2.3.4", "cmp_hash": "abc"}},
		{RequestID: 2, Features: FeatureSet{"source_ip": "1.2.3.4", "cmp_hash": "abc"}},
		{RequestID: 3, Features: FeatureSet{"source_ip": "1.2.3.4", "cmp_hash": "abc"}},
	}
	weights := WeightMap{"source_ip": 0.9, "cmp_hash": 0.8}

	clusters := ClusterUnmatched(requests, weights, 1.0)
	assert.Equal(t, 1, len(clusters), "all requests should be in one cluster")
	assert.Equal(t, 3, len(clusters[0]))
}

func TestClusterUnmatched_TwoDistinctGroups(t *testing.T) {
	requests := []EnrichedRequest{
		{RequestID: 1, Features: FeatureSet{"source_ip": "1.2.3.4", "cmp_hash": "abc"}},
		{RequestID: 2, Features: FeatureSet{"source_ip": "1.2.3.4", "cmp_hash": "abc"}},
		{RequestID: 3, Features: FeatureSet{"source_ip": "9.9.9.9", "cmp_hash": "xyz"}},
		{RequestID: 4, Features: FeatureSet{"source_ip": "9.9.9.9", "cmp_hash": "xyz"}},
	}
	weights := WeightMap{"source_ip": 0.9, "cmp_hash": 0.8}

	clusters := ClusterUnmatched(requests, weights, 1.0)
	assert.Equal(t, 2, len(clusters), "should produce two clusters")
}

func TestClusterUnmatched_NoMatches(t *testing.T) {
	requests := []EnrichedRequest{
		{RequestID: 1, Features: FeatureSet{"source_ip": "1.1.1.1"}},
		{RequestID: 2, Features: FeatureSet{"source_ip": "2.2.2.2"}},
		{RequestID: 3, Features: FeatureSet{"source_ip": "3.3.3.3"}},
	}
	weights := WeightMap{"source_ip": 0.9}

	clusters := ClusterUnmatched(requests, weights, 1.0)
	assert.Equal(t, 3, len(clusters), "each request should be its own cluster")
}

func TestClusterUnmatched_Empty(t *testing.T) {
	clusters := ClusterUnmatched(nil, WeightMap{}, 1.0)
	assert.Nil(t, clusters)
}

func TestClusterUnmatched_TransitiveClustering(t *testing.T) {
	// A matches B on source_ip, B matches C on cmp_hash.
	// A and C don't directly match but should be in the same cluster
	// via transitive closure through B.
	requests := []EnrichedRequest{
		{RequestID: 1, Features: FeatureSet{"source_ip": "1.2.3.4", "cmp_hash": "aaa"}},
		{RequestID: 2, Features: FeatureSet{"source_ip": "1.2.3.4", "cmp_hash": "bbb"}},
		{RequestID: 3, Features: FeatureSet{"source_ip": "9.9.9.9", "cmp_hash": "bbb"}},
	}
	weights := WeightMap{"source_ip": 0.9, "cmp_hash": 0.8}

	clusters := ClusterUnmatched(requests, weights, 0.8)
	assert.Equal(t, 1, len(clusters), "transitive closure should merge all into one cluster")
	assert.Equal(t, 3, len(clusters[0]))
}
