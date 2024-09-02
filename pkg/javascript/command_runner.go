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

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"lophiid/pkg/util"
	"os/exec"
	"time"
)

type CommandRunner interface {
}

// SingleCommandRunner runs a single command. It is designed for usage by
// Javascript and this shows in the way values are returned and stored.
type SingleCommandRunner struct {
	Stdout          bytes.Buffer `json:"stdout"`
	Stderr          bytes.Buffer `json:"stderr"`
	Error           error
	allowedCommands []string
	commandTimeout  time.Duration
}

type CommandRunnerWrapper struct {
	allowedCommands []string
	commandTimeout  time.Duration
}

func (c *CommandRunnerWrapper) GetCommandRunner() *SingleCommandRunner {
	return NewSingleCommandRunner(c.allowedCommands, c.commandTimeout)
}

func NewSingleCommandRunner(allowedCommands []string, commandTimeout time.Duration) *SingleCommandRunner {
	return &SingleCommandRunner{
		allowedCommands: allowedCommands,
		commandTimeout:  commandTimeout,
	}
}

func (s *SingleCommandRunner) GetStdout() string {
	return s.Stdout.String()
}

func (s *SingleCommandRunner) GetStderr() string {
	return s.Stderr.String()
}

// RunCommand runs a command and returns true if it was successful. The command
// needs to be in the allowedCommands list.
func (s *SingleCommandRunner) RunCommand(command string, args ...string) bool {
	if !util.Contains(s.allowedCommands, command) {
		slog.Error("command is not allowed", slog.String("command", command))
		s.Error = fmt.Errorf("command %s is not allowed", command)
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdout = &s.Stdout
	cmd.Stderr = &s.Stderr

	if err := cmd.Start(); err != nil {
		s.Error = err
		slog.Error("command failed to start", slog.String("error", err.Error()), slog.String("stderr", s.Stderr.String()))
		return false
	}

	if err := cmd.Wait(); err != nil {
		s.Error = err
		slog.Error("command failed", slog.String("error", err.Error()), slog.String("stderr", s.Stderr.String()))
		return false
	}

	return true
}
