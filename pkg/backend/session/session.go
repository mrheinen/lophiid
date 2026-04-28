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
	"lophiid/pkg/analysis"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"time"
)

type SessionManager interface {
	CleanupStaleSessions(limit int64) (int, error)
	GetCachedSession(ip string) (*models.Session, error)
	UpdateCachedSession(ip string, session *models.Session) error
	StartSession(ip string) (*models.Session, error)
	EndSession(session *models.Session) error
	PersistActiveSessions() error
	LoadActiveSessions() error
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

	for i := range res {
		if err := d.EndSession(&res[i]); err != nil {
			slog.Error("error ending session", slog.String("ip", res[i].IP), slog.String("error", err.Error()))
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
	if !session.LastRequestAt.IsZero() {
		session.EndedAt = session.LastRequestAt
	} else {
		session.EndedAt = time.Now().UTC()
	}

	profile, err := analysis.GetSessionBehaviorProfile(session.RequestGaps)
	if err != nil {
		slog.Error("error getting behavior profile", slog.String("ip", session.IP), slog.String("error", err.Error()))
	} else {
		session.BehaviorCV = profile.OverallCV
		session.BehaviorHasBursts = profile.HasBursts
		session.BehaviorIsHuman = profile.IsHuman()
		session.BehaviorFinalGaps = profile.FinalGaps
	}

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

// PersistActiveSessions writes all sessions currently held in the cache to the
// database. Sessions are kept active (Active remains true) so that they can be
// reloaded on the next startup. This is intended to be called during a graceful
// shutdown before the database connection is closed.
func (d *DatabaseSessionManager) PersistActiveSessions() error {
	sessions := d.activeSessions.GetAsMap()

	slog.Info("Persisting sessions", slog.Int("count", len(sessions)))
	var firstErr error
	for _, session := range sessions {
		session.SyncRuleIDsFromMap()
		if err := d.dbClient.Update(session); err != nil {
			slog.Error("error persisting session on shutdown", slog.String("ip", session.IP), slog.String("error", err.Error()))
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// LoadActiveSessions loads all sessions marked active in the database into the
// in-memory cache. It is intended to be called during startup after a graceful
// shutdown to restore the previous session state.
//
// Note that this method does not take into account how long sessions already
// were in the cache. It just loads them and by doing so the sessions will again
// get the full expiration time.
func (d *DatabaseSessionManager) LoadActiveSessions() error {
	var offset int64
	const pageSize = 250
	for {
		res, err := d.dbClient.SearchSession(offset, pageSize, "active:true")
		if err != nil {
			return fmt.Errorf("error loading active sessions: %w", err)
		}
		if len(res) == 0 {
			break
		}

		for i := range res {
			sess := &res[i]
			sess.SyncRuleIDsToMap()
			d.activeSessions.Store(sess.IP, sess)
			slog.Info("restored active session from database", slog.String("ip", sess.IP), slog.Int64("session_id", sess.ID))
		}

		if int64(len(res)) < pageSize {
			break
		}
		offset += pageSize
	}
	d.metrics.sessionsActiveGauge.Set(float64(d.activeSessions.Count()))
	return nil
}

// StartNewSession starts a new session for the given IP and stores the session
// in the cache.
func (d *DatabaseSessionManager) StartSession(ip string) (*models.Session, error) {
	newSession := models.NewSession()
	newSession.Active = true
	newSession.KillChainProcessStatus = constants.KillChainProcessStatusNotMonitored
	newSession.StartedAt = time.Now().UTC()
	newSession.IP = ip

	dm, err := d.dbClient.Insert(newSession)
	if err != nil {
		return nil, fmt.Errorf("error inserting session: %w", err)
	}

	retSession := dm.(*models.Session)
	d.activeSessions.Store(ip, retSession)
	d.metrics.sessionsActiveGauge.Set(float64(d.activeSessions.Count()))
	return retSession, nil
}
