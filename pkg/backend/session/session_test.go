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
	"testing"
	"time"
)

func TestSessionManagerCache(t *testing.T) {
	dbClient := database.FakeDatabaseClient{
		ErrorToReturn: nil,
	}

	sm := NewDatabaseSessionManager(&dbClient, 5*time.Minute)

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

	session.ID = 43
	session, _ = sm.GetCachedSession(sessionKey)
	if session.ID != 43 {
		t.Errorf("unexpected session ID: %d", session.ID)
	}
}

func TestSessionManagerCleansStaleSessions(t *testing.T) {
	dbClient := database.FakeDatabaseClient{
		SessionToReturn: database.Session{},
		ErrorToReturn:   nil,
	}

	sm := NewDatabaseSessionManager(&dbClient, 5*time.Minute)

	cnt, err := sm.CleanupStaleSessions(10)
	if err != nil {
		t.Errorf("error cleaning up sessions: %s", err.Error())
	}

	if cnt != 1 {
		t.Errorf("expected 1 stale session, got %d", cnt)
	}
}

func TestSessionManagerEndSession(t *testing.T) {
	dbClient := database.FakeDatabaseClient{
		ErrorToReturn: nil,
	}

	sess := database.Session{
		ID:     42,
		Active: true,
	}

	sm := NewDatabaseSessionManager(&dbClient, 5*time.Minute)
	if err := sm.EndSession(&sess); err != nil {
		t.Errorf("error ending session: %s", err.Error())
	}

	dmSess := dbClient.LastDataModelSeen.(*database.Session)
	if dmSess.ID != 42 {
		t.Errorf("expected session to be ended, got %d", dmSess.ID)
	}

	if dmSess.Active != false {
		t.Errorf("expected session to be ended, got %t", dmSess.Active)
	}
}