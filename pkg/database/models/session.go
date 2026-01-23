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
	ID                int64  `ksql:"id,skipInserts" json:"id" doc:"Database ID for the session"`
	Active            bool   `ksql:"active" json:"active" doc:"Is the session active"`
	IP                string `ksql:"ip" json:"ip" doc:"IP of the client"`
	LastRuleServed    ContentRule
	RuleIDsServed     map[int64]int64
	CreatedAt         time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"Creation date of the session in the database (not session start!)"`
	UpdatedAt         time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at" doc:"Date and time of last update"`
	StartedAt         time.Time `ksql:"started_at" json:"started_at" doc:"Start time of the session"`
	EndedAt           time.Time `ksql:"ended_at" json:"ended_at" doc:"End time of the session"`
	BehaviorCV        float64   `ksql:"behavior_cv" json:"behavior_cv" doc:"The behavior CV"`
	BehaviorIsHuman   bool      `ksql:"behavior_is_human" json:"behavior_is_human" doc:"Is the behavior of the session human-like"`
	BehaviorHasBursts bool      `ksql:"behavior_has_bursts" json:"behavior_has_bursts" doc:"Does the behavior of the session have bursts"`
	BehaviorFinalGaps []float64 `ksql:"behavior_final_gaps" json:"behavior_final_gaps" doc:"The final gaps of the behavior of the session"`
	RequestCount      int64
	RequestGaps       []float64
	LastRequestAt     time.Time
	Mu                sync.RWMutex
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

// NewSession creates a new session.
func NewSession() *Session {
	return &Session{
		RequestCount:  0,
		RuleIDsServed: make(map[int64]int64),
	}
}
