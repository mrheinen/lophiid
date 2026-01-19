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
package analysis

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGroupBurstGaps(t *testing.T) {
	tests := []struct {
		name      string
		gaps      []float64
		threshold float64
		expected  []float64
	}{
		{
			name:      "example from user",
			gaps:      []float64{0.1, 0.2, 0.3, 1.5, 1.6, 1.7},
			threshold: 1.0,
			expected:  []float64{0.2, 1.5, 1.6, 1.7},
		},
		{
			name:      "no bursts",
			gaps:      []float64{2.0, 3.0, 4.0},
			threshold: 1.0,
			expected:  []float64{2.0, 3.0, 4.0},
		},
		{
			name:      "all bursts",
			gaps:      []float64{0.1, 0.2, 0.3, 0.4},
			threshold: 1.0,
			expected:  []float64{0.25},
		},
		{
			name:      "alternating bursts and non-bursts",
			gaps:      []float64{0.1, 0.2, 2.0, 0.3, 0.4, 3.0},
			threshold: 1.0,
			expected:  []float64{0.15, 2.0, 0.35, 3.0},
		},
		{
			name:      "single gap below threshold",
			gaps:      []float64{0.5},
			threshold: 1.0,
			expected:  []float64{0.5},
		},
		{
			name:      "single gap above threshold",
			gaps:      []float64{2.0},
			threshold: 1.0,
			expected:  []float64{2.0},
		},
		{
			name:      "empty input",
			gaps:      []float64{},
			threshold: 1.0,
			expected:  []float64{},
		},
		{
			name:      "burst at end",
			gaps:      []float64{2.0, 3.0, 0.1, 0.2, 0.3},
			threshold: 1.0,
			expected:  []float64{2.0, 3.0, 0.2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GroupBurstGaps(tt.gaps, tt.threshold)
			assert.Equal(t, len(tt.expected), len(result), "result length mismatch")
			for i := range tt.expected {
				assert.InDelta(t, tt.expected[i], result[i], 0.0001, "gap at index %d", i)
			}
		})
	}
}

func TestCalculateCoefficientOfVariation(t *testing.T) {
	tests := []struct {
		name        string
		gaps        []float64
		expectedCV  float64
		expectError bool
	}{
		{
			name:        "identical gaps - zero variance",
			gaps:        []float64{1.0, 1.0, 1.0, 1.0, 1.0},
			expectedCV:  0.0,
			expectError: false,
		},
		{
			name:        "not enough data",
			gaps:        []float64{1.0, 2.0},
			expectError: true,
		},
		{
			name:        "negative gap",
			gaps:        []float64{1.0, 2.0, -1.0, 3.0, 4.0},
			expectError: true,
		},
		{
			name:        "near-zero mean (instant requests)",
			gaps:        []float64{0.00001, 0.00001, 0.00001, 0.00001},
			expectedCV:  0.0,
			expectError: false,
		},
		{
			name:        "high variance (human-like)",
			gaps:        []float64{1.0, 5.0, 2.0, 8.0, 3.0},
			expectedCV:  0.6,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cv, err := CalculateCoefficientOfVariation(tt.gaps)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.expectedCV == 0.0 {
					assert.Equal(t, 0.0, cv)
				} else {
					assert.InDelta(t, tt.expectedCV, cv, 0.1)
				}
			}
		})
	}
}
