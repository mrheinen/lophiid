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
package session

import (
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util/constants"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestSessionManagerCache(t *testing.T) {
	dbClient := database.FakeDatabaseClient{
		ErrorToReturn: nil,
	}

	reg := prometheus.NewRegistry()
	metrics := CreateSessionMetrics(reg)

	sm := NewDatabaseSessionManager(&dbClient, 5*time.Minute, metrics)

	sessionKey := "1.1.1.1"
	session, err := sm.StartSession(sessionKey)
	if err != nil {
		t.Errorf("error starting session: %s", err.Error())
	}

	// This is kinda hacky but the goal is to make sure that we work with pointers
	// and that whenever we get the session we update it immediately in the cache.
	session.ID = 42
	session, _ = sm.GetCachedSession(sessionKey)
	if session.ID != 42 {
		t.Errorf("unexpected session ID: %d", session.ID)
	}

	// Check the gauge.
	m := testutil.ToFloat64(metrics.sessionsActiveGauge)
	if m != 1 {
		t.Errorf("sessionsActiveGauge should be 1, got %f", m)
	}

	session.ID = 43
	session, _ = sm.GetCachedSession(sessionKey)
	if session.ID != 43 {
		t.Errorf("unexpected session ID: %d", session.ID)
	}
}

func TestSessionManagerCleansStaleSessions(t *testing.T) {
	dbClient := database.FakeDatabaseClient{
		SessionToReturn: models.Session{},
		ErrorToReturn:   nil,
	}

	reg := prometheus.NewRegistry()
	metrics := CreateSessionMetrics(reg)

	sm := NewDatabaseSessionManager(&dbClient, 5*time.Minute, metrics)

	cnt, err := sm.CleanupStaleSessions(10)
	if err != nil {
		t.Errorf("error cleaning up sessions: %s", err.Error())
	}

	if cnt != 1 {
		t.Errorf("expected 1 stale session, got %d", cnt)
	}
}

func TestStartSession_KillChainStatusNotMonitored(t *testing.T) {
	dbClient := database.FakeDatabaseClient{ErrorToReturn: nil}

	reg := prometheus.NewRegistry()
	metrics := CreateSessionMetrics(reg)

	sm := NewDatabaseSessionManager(&dbClient, 5*time.Minute, metrics)

	sess, err := sm.StartSession("1.2.3.4")
	if err != nil {
		t.Fatalf("error starting session: %s", err.Error())
	}

	if sess.KillChainProcessStatus != constants.KillChainProcessStatusNotMonitored {
		t.Errorf("expected NOT_MONITORED, got %s", sess.KillChainProcessStatus)
	}
}

func TestPersistActiveSessions(t *testing.T) {
	dbClient := database.FakeDatabaseClient{
		ErrorToReturn: nil,
	}

	reg := prometheus.NewRegistry()
	metrics := CreateSessionMetrics(reg)

	sm := NewDatabaseSessionManager(&dbClient, 5*time.Minute, metrics)

	sess, err := sm.StartSession("1.2.3.4")
	if err != nil {
		t.Fatalf("error starting session: %s", err.Error())
	}

	sess.LastAppIDServed = 42
	sess.ServedRuleWithContent(10, 100)
	sess.ServedRuleWithContent(20, 200)

	if err := sm.PersistActiveSessions(); err != nil {
		t.Fatalf("error persisting sessions: %s", err.Error())
	}

	persisted, ok := dbClient.LastDataModelSeen.(*models.Session)
	if !ok {
		t.Fatalf("expected *models.Session, got %T", dbClient.LastDataModelSeen)
	}

	if persisted.LastAppIDServed != 42 {
		t.Errorf("expected LastAppIDServed=42, got %d", persisted.LastAppIDServed)
	}

	if persisted.Active != true {
		t.Errorf("expected Active=true after persist, got false")
	}

	if len(persisted.RuleIDsServedDB)%2 != 0 {
		t.Errorf("expected even-length RuleIDsServedDB, got %d", len(persisted.RuleIDsServedDB))
	}

	rebuilt := make(map[int64]int64)
	for i := 0; i+1 < len(persisted.RuleIDsServedDB); i += 2 {
		rebuilt[persisted.RuleIDsServedDB[i]] = persisted.RuleIDsServedDB[i+1]
	}
	if rebuilt[10] != 100 {
		t.Errorf("expected rule 10 -> content 100, got %d", rebuilt[10])
	}
	if rebuilt[20] != 200 {
		t.Errorf("expected rule 20 -> content 200, got %d", rebuilt[20])
	}
}

func TestLoadActiveSessions(t *testing.T) {
	dbClient := database.FakeDatabaseClient{
		ErrorToReturn: nil,
		SessionToReturn: models.Session{
			ID:              7,
			Active:          true,
			IP:              "5.6.7.8",
			LastAppIDServed: 77,
			RuleIDsServedDB: []int64{10, 100, 20, 200},
		},
	}

	reg := prometheus.NewRegistry()
	metrics := CreateSessionMetrics(reg)

	sm := NewDatabaseSessionManager(&dbClient, 5*time.Minute, metrics)

	if err := sm.LoadActiveSessions(); err != nil {
		t.Fatalf("error loading active sessions: %s", err.Error())
	}

	loaded, err := sm.GetCachedSession("5.6.7.8")
	if err != nil {
		t.Fatalf("expected session in cache: %s", err.Error())
	}

	if loaded.ID != 7 {
		t.Errorf("expected session ID=7, got %d", loaded.ID)
	}

	if loaded.LastAppIDServed != 77 {
		t.Errorf("expected LastAppIDServed=77, got %d", loaded.LastAppIDServed)
	}

	if loaded.RuleIDsServed[10] != 100 {
		t.Errorf("expected rule 10 -> content 100, got %d", loaded.RuleIDsServed[10])
	}
	if loaded.RuleIDsServed[20] != 200 {
		t.Errorf("expected rule 20 -> content 200, got %d", loaded.RuleIDsServed[20])
	}

	m := testutil.ToFloat64(metrics.sessionsActiveGauge)
	if m != 1 {
		t.Errorf("sessionsActiveGauge should be 1, got %f", m)
	}
}

func TestLoadActiveSessionsNoLastRule(t *testing.T) {
	dbClient := database.FakeDatabaseClient{
		ErrorToReturn: nil,
		SessionToReturn: models.Session{
			ID:     8,
			Active: true,
			IP:     "9.9.9.9",
		},
	}

	reg := prometheus.NewRegistry()
	metrics := CreateSessionMetrics(reg)

	sm := NewDatabaseSessionManager(&dbClient, 5*time.Minute, metrics)

	if err := sm.LoadActiveSessions(); err != nil {
		t.Fatalf("error loading active sessions: %s", err.Error())
	}

	loaded, err := sm.GetCachedSession("9.9.9.9")
	if err != nil {
		t.Fatalf("expected session in cache: %s", err.Error())
	}

	if loaded.LastAppIDServed != 0 {
		t.Errorf("expected zero LastAppIDServed, got %d", loaded.LastAppIDServed)
	}
	if loaded.RuleIDsServed == nil {
		t.Errorf("expected RuleIDsServed to be initialised, got nil")
	}
}

func TestSessionManagerEndSession(t *testing.T) {
	dbClient := database.FakeDatabaseClient{
		ErrorToReturn: nil,
	}

	sess := models.Session{
		ID:     42,
		Active: true,
	}

	reg := prometheus.NewRegistry()
	metrics := CreateSessionMetrics(reg)

	sm := NewDatabaseSessionManager(&dbClient, 5*time.Minute, metrics)
	if err := sm.EndSession(&sess); err != nil {
		t.Errorf("error ending session: %s", err.Error())
	}

	dmSess := dbClient.LastDataModelSeen.(*models.Session)
	if dmSess.ID != 42 {
		t.Errorf("expected session to be ended, got %d", dmSess.ID)
	}

	if dmSess.Active != false {
		t.Errorf("expected session to be ended, got %t", dmSess.Active)
	}
}
