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
	"lophiid/pkg/database/models"
)

type FakeSessionManager struct {
	SessionToReturn models.Session
	ErrorToReturn   error
}

func (f *FakeSessionManager) CleanupStaleSessions(limit int64) (int, error) {
	return 0, f.ErrorToReturn
}

func (f *FakeSessionManager) GetCachedSession(ip string) (*models.Session, error) {
	return &f.SessionToReturn, f.ErrorToReturn
}

func (f *FakeSessionManager) UpdateCachedSession(ip string, session *models.Session) error {
	return f.ErrorToReturn
}

func (f *FakeSessionManager) StartSession(ip string) (*models.Session, error) {
	return &f.SessionToReturn, f.ErrorToReturn
}

func (f *FakeSessionManager) EndSession(session *models.Session) error {
	return f.ErrorToReturn
}
