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
package javascript

import (
	"log/slog"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm/shell"
)

type Shell struct {
	shellClient shell.ShellClientInterface
	request     *models.Request
}

// RunCommand is a wrapper around the shell client and returns the command
// output as a string.
func (s *Shell) RunCommand(cmd string) string {
	res, err := s.shellClient.RunCommand(s.request, cmd)

	if err != nil {
		slog.Error("error running command", slog.String("error", err.Error()), slog.String("cmd", cmd))
		return ""
	}

	return res.Output
}
