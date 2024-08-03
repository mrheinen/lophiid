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
//
package backend

import (
	"loophid/pkg/database"
	"sync"
)

type RequestQueue struct {
	mu   sync.Mutex
	reqs []*database.Request
}

func (r *RequestQueue) Pop() *database.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.reqs) == 0 {
		return nil
	}

	ret := r.reqs[0]
	r.reqs = r.reqs[1:]
	return ret
}

func (r *RequestQueue) Length() int {
	return len(r.reqs)
}

func (r *RequestQueue) Push(req *database.Request) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	r.mu.Unlock()
}
