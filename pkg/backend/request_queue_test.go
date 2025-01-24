// Lophiid distributed honeypot
// Copyright (C) 2024 Niels Heinen
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
package backend

import (
	"lophiid/pkg/database/models"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestQueue(t *testing.T) {
	req := models.Request{}
	q := RequestQueue{}

	assert.Nil(t, q.Pop(), "Popping an empty queue should yield nil")

	q.Push(&req)
	assert.Equal(t, 1, q.Length(), "Queue length should be 1 after pushing")

	assert.Equal(t, &req, q.Pop(), "Popped request should match pushed request")
	assert.Equal(t, 0, q.Length(), "Queue should be empty after popping")
}
