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
package models

import (
	"sync"
	"time"
)

type Session struct {
	ID                     int64  `ksql:"id,skipInserts" json:"id" doc:"Database ID for the session"`
	Active                 bool   `ksql:"active" json:"active" doc:"Is the session active"`
	IP                     string `ksql:"ip" json:"ip" doc:"IP of the client"`
	LastAppIDServed        int64  `ksql:"last_app_id_served" json:"last_app_id_served" doc:"App ID of the last content rule served in this session"`
	RuleIDsServed          map[int64]int64
	RuleIDsServedDB        []int64   `ksql:"rule_ids_served" json:"rule_ids_served" doc:"Flat interleaved pairs of [ruleID, contentID, ...] for DB storage"`
	CreatedAt              time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"Creation date of the session in the database (not session start!)"`
	UpdatedAt              time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at" doc:"Date and time of last update"`
	StartedAt              time.Time `ksql:"started_at" json:"started_at" doc:"Start time of the session"`
	EndedAt                time.Time `ksql:"ended_at" json:"ended_at" doc:"End time of the session"`
	BehaviorCV             float64   `ksql:"behavior_cv" json:"behavior_cv" doc:"The behavior CV"`
	BehaviorIsHuman        bool      `ksql:"behavior_is_human" json:"behavior_is_human" doc:"Is the behavior of the session human-like"`
	BehaviorHasBursts      bool      `ksql:"behavior_has_bursts" json:"behavior_has_bursts" doc:"Does the behavior of the session have bursts"`
	BehaviorFinalGaps      []float64 `ksql:"behavior_final_gaps"            json:"behavior_final_gaps"            doc:"The final gaps of the behavior of the session"`
	KillChainProcessStatus string    `ksql:"kill_chain_process_status" json:"kill_chain_process_status" doc:"Kill chain analysis status: PENDING, DONE, FAILED or SKIPPED"`
	RequestCount           int64     `ksql:"request_count" json:"request_count" doc:"Number of requests in this session"`
	RequestGaps            []float64 `ksql:"request_gaps" json:"request_gaps" doc:"Inter-request gap durations in seconds"`
	LastRequestAt          time.Time `ksql:"last_request_at" json:"last_request_at" doc:"Time of the last request in this session"`
	Mu                     sync.RWMutex
}

func (c *Session) ModelID() int64 { return c.ID }

func (c *Session) AddRequestGap(gap float64) {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	c.RequestGaps = append(c.RequestGaps, gap)
}

func (c *Session) IncreaseRequestCount() {
	c.Mu.Lock()
	c.RequestCount++
	c.Mu.Unlock()
}

// SetKillChainProcessStatus sets the kill chain process status. Does not
// validate the status, callers are expected to use the enum values directly to
// avoid using the wrong status.
func (c *Session) SetKillChainProcessStatus(status string) {
	c.Mu.Lock()
	c.KillChainProcessStatus = status
	c.Mu.Unlock()
}

func (c *Session) SetLastRequestAt(t time.Time) {
	c.Mu.Lock()
	c.LastRequestAt = t
	c.Mu.Unlock()
}

// HasServedRule checks if the session has served the given rule.
func (c *Session) HasServedRule(ruleID int64) bool {
	c.Mu.RLock()
	defer c.Mu.RUnlock()
	_, ok := c.RuleIDsServed[ruleID]
	return ok
}

// ServedRuleWithContent updates the session with the given rule and content ID.
func (c *Session) ServedRuleWithContent(ruleID int64, contentID int64) {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	c.RuleIDsServed[ruleID] = contentID
}

// SyncRuleIDsFromMap converts the in-memory RuleIDsServed map into the flat
// interleaved RuleIDsServedDB slice for database persistence.
func (c *Session) SyncRuleIDsFromMap() {
	c.Mu.RLock()
	defer c.Mu.RUnlock()
	c.RuleIDsServedDB = make([]int64, 0, len(c.RuleIDsServed)*2)
	for ruleID, contentID := range c.RuleIDsServed {
		c.RuleIDsServedDB = append(c.RuleIDsServedDB, ruleID, contentID)
	}
}

// SyncRuleIDsToMap converts the flat interleaved RuleIDsServedDB slice (loaded
// from the database) back into the in-memory RuleIDsServed map.
func (c *Session) SyncRuleIDsToMap() {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	c.RuleIDsServed = make(map[int64]int64)
	for i := 0; i+1 < len(c.RuleIDsServedDB); i += 2 {
		c.RuleIDsServed[c.RuleIDsServedDB[i]] = c.RuleIDsServedDB[i+1]
	}
}

// NewSession creates a new session.
func NewSession() *Session {
	return &Session{
		RequestCount:  0,
		RuleIDsServed: make(map[int64]int64),
	}
}
