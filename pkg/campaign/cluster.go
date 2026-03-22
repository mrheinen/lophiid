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
package campaign

// ClusterUnmatched performs single-linkage clustering on unmatched enriched
// requests using pairwise weighted similarity. Returns groups of request
// indices that form clusters (score >= threshold).
func ClusterUnmatched(requests []EnrichedRequest, weights WeightMap, threshold float64) [][]int {
	n := len(requests)
	if n == 0 {
		return nil
	}

	// Union-Find for clustering.
	parent := make([]int, n)
	rank := make([]int, n)
	for i := range parent {
		parent[i] = i
	}

	var find func(int) int
	find = func(x int) int {
		if parent[x] != x {
			parent[x] = find(parent[x])
		}
		return parent[x]
	}

	union := func(x, y int) {
		px, py := find(x), find(y)
		if px == py {
			return
		}
		if rank[px] < rank[py] {
			px, py = py, px
		}
		parent[py] = px
		if rank[px] == rank[py] {
			rank[px]++
		}
	}

	// Pairwise comparison.
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			score := ScoreFeatureSets(requests[i].Features, requests[j].Features, weights)
			if score >= threshold {
				union(i, j)
			}
		}
	}

	// Group by root.
	groups := make(map[int][]int)
	for i := 0; i < n; i++ {
		root := find(i)
		groups[root] = append(groups[root], i)
	}

	var result [][]int
	for _, group := range groups {
		result = append(result, group)
	}
	return result
}
