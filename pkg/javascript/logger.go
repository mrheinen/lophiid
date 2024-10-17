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
package javascript

import "log/slog"

// Logger is a simple wrapper for slog that also caches the log messges and
// makes them that way available to the calling Javascript.
type Logger struct {
	Messages []string
}

// Reset resets the log messages
func (l *Logger) Reset() {
	l.Messages = []string{}
}

// GetMessages returns the log messages
func (l *Logger) GetMessages() []string {
	return l.Messages
}

func (l *Logger) Info(message string) {
	l.Messages = append(l.Messages, message)
	slog.Info(message)
}

func (l *Logger) Error(message string) {
	l.Messages = append(l.Messages, message)
	slog.Error(message)
}

func (l *Logger) Warn(message string) {
	l.Messages = append(l.Messages, message)
	slog.Warn(message)
}

func (l *Logger) Debug(message string) {
	l.Messages = append(l.Messages, message)
	slog.Debug(message)
}
