// Lophiid distributed honeypot
// Copyright (C) 2025 Niels Heinen
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

package logutil

import (
	"log/slog"
	"lophiid/pkg/database/models"
)

func Error(msg string, req *models.Request, args ...any) {
	if req == nil {
		slog.Error(msg, args...)
		return
	}
	allArgs := append([]any{slog.Int64("request_id", req.ID), slog.Int64("session_id", req.SessionID)}, args...)
	slog.Error(msg, allArgs...)
}

func Debug(msg string, req *models.Request, args ...any) {
	if req == nil {
		slog.Debug(msg, args...)
		return
	}
	allArgs := append([]any{slog.Int64("request_id", req.ID), slog.Int64("session_id", req.SessionID)}, args...)
	slog.Debug(msg, allArgs...)
}

func Info(msg string, req *models.Request, args ...any) {
	if req == nil {
		slog.Info(msg, args...)
		return
	}
	allArgs := append([]any{slog.Int64("request_id", req.ID), slog.Int64("session_id", req.SessionID)}, args...)
	slog.Info(msg, allArgs...)
}

func Warn(msg string, req *models.Request, args ...any) {
	if req == nil {
		slog.Warn(msg, args...)
		return
	}
	allArgs := append([]any{slog.Int64("request_id", req.ID), slog.Int64("session_id", req.SessionID)}, args...)
	slog.Warn(msg, allArgs...)
}
