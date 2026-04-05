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
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
)

type SafeRules struct {
	mu            sync.Mutex
	rulesPerGroup map[int64][]models.ContentRule
	dbClient      database.DatabaseClient
	stopChan      chan struct{}
}

func NewSafeRules(dbClient database.DatabaseClient) *SafeRules {
	return &SafeRules{
		dbClient:      dbClient,
		stopChan:      make(chan struct{}),
		rulesPerGroup: make(map[int64][]models.ContentRule),
	}
}

// GetRules returns a copy of the content rules.
func (s *SafeRules) Get() map[int64][]models.ContentRule {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make(map[int64][]models.ContentRule, len(s.rulesPerGroup))
	for k, v := range s.rulesPerGroup {
		result[k] = slices.Clone(v)
	}
	return result
}

// Add adds a content rule to a group. It does not check if the rule already
// exists.
func (s *SafeRules) Add(r models.ContentRule, groupID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.rulesPerGroup[groupID]; !ok {
		s.rulesPerGroup[groupID] = []models.ContentRule{r}
	} else {
		s.rulesPerGroup[groupID] = append(s.rulesPerGroup[groupID], r)
	}
}

func (s *SafeRules) GetGroup(groupID int64) []models.ContentRule {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.rulesPerGroup[groupID]; !ok {
		return []models.ContentRule{}
	}

	return slices.Clone(s.rulesPerGroup[groupID])
}

func (s *SafeRules) Set(rules map[int64][]models.ContentRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rulesPerGroup = rules
}

// LoadRules loads the content rules from the database. It first fetches the
// app-per-group mappings and then fetches the rules for each app separately.
func (s *SafeRules) LoadRules() error {
	appPerGroup, err := s.dbClient.GetAppPerGroupJoin()
	if err != nil {
		return fmt.Errorf("getting app per group: %w", err)
	}

	// Build a map of app ID to the group IDs it belongs to, and track which
	// apps we need to fetch rules for.
	appToGroups := map[int64][]int64{}
	for _, apg := range appPerGroup {
		appToGroups[apg.App.ID] = append(appToGroups[apg.App.ID], apg.AppPerGroup.GroupID)
	}

	ruleCount := 0
	finalRules := map[int64][]models.ContentRule{}
	for appID, groupIDs := range appToGroups {
		rules, err := s.dbClient.SearchContentRules(0, 10000, fmt.Sprintf("app_id:%d", appID))
		if err != nil {
			return fmt.Errorf("searching rules for app %d: %w", appID, err)
		}

		for _, rule := range rules {
			if !rule.Enabled || rule.IsDraft {
				slog.Debug("rule disabled or draft", slog.Int64("rule_id", rule.ID), slog.Int64("app_id", rule.AppID))
				continue
			}
			for _, groupID := range groupIDs {
				finalRules[groupID] = append(finalRules[groupID], rule)
				ruleCount++
			}
		}
	}

	slog.Info("loaded rules", slog.Int("rules_count", ruleCount), slog.Int("amount_of_groups", len(finalRules)))
	s.Set(finalRules)
	return nil
}

// Start performs an initial rule load and then starts a goroutine that
// reloads rules from the database on the given interval.
func (s *SafeRules) Start(interval time.Duration) error {
	if err := s.LoadRules(); err != nil {
		return err
	}
	go func() {
		ticker := time.NewTicker(interval)
		for {
			select {
			case <-s.stopChan:
				ticker.Stop()
				return
			case <-ticker.C:
				cl := len(s.Get())
				if err := s.LoadRules(); err != nil {
					slog.Error("reloading rules", slog.String("error", err.Error()))
				}
				nl := len(s.Get())
				if cl != nl {
					slog.Info("Rules updated", slog.Int("from", cl), slog.Int("to", nl))
				}
			}
		}
	}()
	return nil
}

// Stop stops the rule reloading goroutine started by Start.
func (s *SafeRules) Stop() {
	s.stopChan <- struct{}{}
}
