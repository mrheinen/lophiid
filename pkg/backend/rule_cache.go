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
	"fmt"
	"sync"
	"time"
)

type RuleVsContentCache struct {
	mu      sync.Mutex
	entries map[string]map[string]time.Time
	timeout time.Duration
}

func NewRuleVsContentCache(timeout time.Duration) *RuleVsContentCache {
	return &RuleVsContentCache{
		entries: make(map[string]map[string]time.Time),
		timeout: timeout,
	}
}

func (r *RuleVsContentCache) Store(sourceIp string, ruleId int64, contentId int64) {
	key := fmt.Sprintf("%d-%d", ruleId, contentId)

	r.mu.Lock()
	if _, ok := r.entries[sourceIp]; !ok {
		r.entries[sourceIp] = make(map[string]time.Time)
	}
	r.entries[sourceIp][key] = time.Now()
	r.mu.Unlock()
}

func (r *RuleVsContentCache) Has(sourceIp string, ruleId int64, contentId int64) bool {
	key := fmt.Sprintf("%d-%d", ruleId, contentId)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[sourceIp]; !ok {
		return false
	}
	_, ok := r.entries[sourceIp][key]
	return ok
}

func (r *RuleVsContentCache) CleanupExpired() {
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()
	for ip, keys := range r.entries {
		for key, t := range keys {
			if now.Sub(t) > r.timeout {
				delete(r.entries[ip], key)
			}
		}
		if len(r.entries[ip]) == 0 {
			delete(r.entries, ip)
		}
	}
}
