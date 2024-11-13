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
	"fmt"
	"log/slog"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util"
	"time"
)

type SessionManager interface {
	CleanupStaleSessions(limit int64) (int, error)
	GetCachedSession(ip string) (*models.Session, error)
	UpdateCachedSession(ip string, session *models.Session) error
	StartSession(ip string) (*models.Session, error)
	EndSession(session *models.Session) error
}

// DatabaseSessionManager manages the sessions in the database. It does use a
// cache to minimalize the database calls and only writes to the database upon
// creation of a session and its expiration.
type DatabaseSessionManager struct {
	activeSessions *util.StringMapCache[*models.Session]
	dbClient       database.DatabaseClient
	metrics        *SessionMetrics
}

// NewDatabaseSessionManager returns a new session manager.
func NewDatabaseSessionManager(dbClient database.DatabaseClient, sessionTimeout time.Duration, metrics *SessionMetrics) *DatabaseSessionManager {
	cache := util.NewStringMapCache[*models.Session]("session cache", sessionTimeout)

	sm := &DatabaseSessionManager{
		dbClient:       dbClient,
		activeSessions: cache,
		metrics:        metrics,
	}

	cache.StartWithCallback(sm.SaveExpiredSession)
	return sm
}

// CleanupStaleSessions cleans up the stale sessions. It returns the number of
// sessions cleaned up so that the caller can deterime whether they want to call
// the method again.
func (d *DatabaseSessionManager) CleanupStaleSessions(limit int64) (int, error) {

	res, err := d.dbClient.SearchSession(0, limit, "active:true")
	if err != nil {
		return 0, fmt.Errorf("error fetching session: %w", err)
	}

	if len(res) == 0 {
		return 0, nil
	}

	slog.Warn("Found stale sessions. Cleaning the up", slog.Int("count", len(res)))

	for _, sess := range res {
		if err := d.EndSession(&sess); err != nil {
			slog.Error("error ending session", slog.String("ip", sess.IP), slog.String("error", err.Error()))
			// We do not return here as we want the try to cleanup the other sessions
			// as well.
		}
	}

	return len(res), nil
}

// EndSession ends the active session and updates the database. The caller
// is responsible for modifying the cache.
func (d *DatabaseSessionManager) EndSession(session *models.Session) error {
	session.Active = false
	session.EndedAt = time.Now().UTC()

	if err := d.dbClient.Update(session); err != nil {
		return fmt.Errorf("error updating session: %w", err)
	}

	return nil
}

// GetSessionFromCache returns the active session for the given IP. It
// returns nil if no session is active.
func (d *DatabaseSessionManager) GetCachedSession(ip string) (*models.Session, error) {
	sess, err := d.activeSessions.Get(ip)
	if err != nil {
		return nil, fmt.Errorf("error fetching session: %w", err)
	}
	return *sess, nil
}

// UpdateSessionInCache stores the session in the cache. It also causes the
// session timeout to be updated so that it will restart.
func (d *DatabaseSessionManager) UpdateCachedSession(ip string, session *models.Session) error {
	return d.activeSessions.Update(ip, session)
}

// SaveSession is a callback function for the cache and called whenever an item
// in the cache expires. Saves the session in the database.
func (d *DatabaseSessionManager) SaveExpiredSession(session *models.Session) bool {
	if err := d.EndSession(session); err != nil {
		slog.Error("error saving session", slog.String("ip", session.IP), slog.String("error", err.Error()))
		return false
	}
	return true
}

// StartNewSession starts a new session for the given IP and stores the session
// in the cache.
func (d *DatabaseSessionManager) StartSession(ip string) (*models.Session, error) {
	d.metrics.sessionsActiveGauge.Set(float64(d.activeSessions.Count()))
	newSession := models.NewSession()
	newSession.Active = true
	newSession.StartedAt = time.Now().UTC()
	newSession.IP = ip

	dm, err := d.dbClient.Insert(newSession)
	if err != nil {
		return nil, fmt.Errorf("error inserting session: %w", err)
	}

	retSession := dm.(*models.Session)
	d.activeSessions.Store(ip, retSession)
	return retSession, nil
}
