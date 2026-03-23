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
	"time"

	"github.com/stretchr/testify/assert"
)

func TestComputeBackfillChunks_ExactDivision(t *testing.T) {
	from := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC)
	window := 24 * time.Hour

	chunks := ComputeBackfillChunks(from, to, window)
	assert.Equal(t, 3, len(chunks))

	assert.Equal(t, from, chunks[0].Start)
	assert.Equal(t, from.Add(24*time.Hour), chunks[0].End)

	assert.Equal(t, from.Add(24*time.Hour), chunks[1].Start)
	assert.Equal(t, from.Add(48*time.Hour), chunks[1].End)

	assert.Equal(t, from.Add(48*time.Hour), chunks[2].Start)
	assert.Equal(t, to, chunks[2].End)
}

func TestComputeBackfillChunks_PartialFinalChunk(t *testing.T) {
	from := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2025, 1, 3, 12, 0, 0, 0, time.UTC) // 2.5 days
	window := 24 * time.Hour

	chunks := ComputeBackfillChunks(from, to, window)
	assert.Equal(t, 3, len(chunks))

	// Last chunk should be truncated at 'to'.
	assert.Equal(t, from.Add(48*time.Hour), chunks[2].Start)
	assert.Equal(t, to, chunks[2].End)
}

func TestComputeBackfillChunks_SingleChunk(t *testing.T) {
	from := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	window := 24 * time.Hour

	chunks := ComputeBackfillChunks(from, to, window)
	assert.Equal(t, 1, len(chunks))
	assert.Equal(t, from, chunks[0].Start)
	assert.Equal(t, to, chunks[0].End)
}

func TestComputeBackfillChunks_ZeroDuration(t *testing.T) {
	from := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from // Same time.

	chunks := ComputeBackfillChunks(from, to, 24*time.Hour)
	assert.Equal(t, 0, len(chunks))
}

func TestComputeBackfillChunks_SmallWindow(t *testing.T) {
	from := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2025, 1, 1, 3, 0, 0, 0, time.UTC) // 3 hours
	window := 1 * time.Hour

	chunks := ComputeBackfillChunks(from, to, window)
	assert.Equal(t, 3, len(chunks))
}
