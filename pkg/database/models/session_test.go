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
	"testing"
)

func TestSyncRuleIDsFromMap(t *testing.T) {
	s := NewSession()
	s.RuleIDsServed[10] = 100
	s.RuleIDsServed[20] = 200

	s.SyncRuleIDsFromMap()

	if len(s.RuleIDsServedDB)%2 != 0 {
		t.Fatalf("expected even-length RuleIDsServedDB, got %d", len(s.RuleIDsServedDB))
	}
	if len(s.RuleIDsServedDB) != 4 {
		t.Fatalf("expected 4 elements in RuleIDsServedDB, got %d", len(s.RuleIDsServedDB))
	}

	rebuilt := make(map[int64]int64)
	for i := 0; i+1 < len(s.RuleIDsServedDB); i += 2 {
		rebuilt[s.RuleIDsServedDB[i]] = s.RuleIDsServedDB[i+1]
	}
	if rebuilt[10] != 100 {
		t.Errorf("expected rule 10 -> content 100, got %d", rebuilt[10])
	}
	if rebuilt[20] != 200 {
		t.Errorf("expected rule 20 -> content 200, got %d", rebuilt[20])
	}
}

func TestSyncRuleIDsFromMapEmpty(t *testing.T) {
	s := NewSession()
	s.SyncRuleIDsFromMap()

	if len(s.RuleIDsServedDB) != 0 {
		t.Errorf("expected empty RuleIDsServedDB, got %d elements", len(s.RuleIDsServedDB))
	}
}

func TestSyncRuleIDsToMap(t *testing.T) {
	s := NewSession()
	s.RuleIDsServedDB = []int64{10, 100, 20, 200, 30, 300}

	s.SyncRuleIDsToMap()

	if len(s.RuleIDsServed) != 3 {
		t.Fatalf("expected 3 entries in RuleIDsServed, got %d", len(s.RuleIDsServed))
	}
	if s.RuleIDsServed[10] != 100 {
		t.Errorf("expected rule 10 -> content 100, got %d", s.RuleIDsServed[10])
	}
	if s.RuleIDsServed[20] != 200 {
		t.Errorf("expected rule 20 -> content 200, got %d", s.RuleIDsServed[20])
	}
	if s.RuleIDsServed[30] != 300 {
		t.Errorf("expected rule 30 -> content 300, got %d", s.RuleIDsServed[30])
	}
}

func TestSyncRuleIDsToMapEmpty(t *testing.T) {
	s := NewSession()
	s.SyncRuleIDsToMap()

	if s.RuleIDsServed == nil {
		t.Errorf("expected initialised map, got nil")
	}
	if len(s.RuleIDsServed) != 0 {
		t.Errorf("expected empty map, got %d entries", len(s.RuleIDsServed))
	}
}

func TestSyncRuleIDsToMapOddLength(t *testing.T) {
	s := NewSession()
	s.RuleIDsServedDB = []int64{10, 100, 20}

	s.SyncRuleIDsToMap()

	if len(s.RuleIDsServed) != 1 {
		t.Fatalf("expected 1 complete pair, got %d entries", len(s.RuleIDsServed))
	}
	if s.RuleIDsServed[10] != 100 {
		t.Errorf("expected rule 10 -> content 100, got %d", s.RuleIDsServed[10])
	}
}

func TestSyncRoundTrip(t *testing.T) {
	s := NewSession()
	s.RuleIDsServed[1] = 11
	s.RuleIDsServed[2] = 22
	s.RuleIDsServed[3] = 33

	s.SyncRuleIDsFromMap()
	s.RuleIDsServed = nil
	s.SyncRuleIDsToMap()

	if len(s.RuleIDsServed) != 3 {
		t.Fatalf("expected 3 entries after round-trip, got %d", len(s.RuleIDsServed))
	}
	for ruleID, wantContent := range map[int64]int64{1: 11, 2: 22, 3: 33} {
		if got := s.RuleIDsServed[ruleID]; got != wantContent {
			t.Errorf("rule %d: expected content %d, got %d", ruleID, wantContent, got)
		}
	}
}
