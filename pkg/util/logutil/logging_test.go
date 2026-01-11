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
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"lophiid/pkg/database/models"
)

func TestError(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	slog.SetDefault(logger)
	defer slog.SetDefault(slog.Default())

	for _, test := range []struct {
		description   string
		req           *models.Request
		msg           string
		args          []any
		wantRequestID bool
		wantSessionID bool
	}{
		{
			description:   "with request",
			req:           &models.Request{ID: 123, SessionID: 456},
			msg:           "test error",
			args:          []any{slog.String("key", "value")},
			wantRequestID: true,
			wantSessionID: true,
		},
		{
			description:   "with nil request",
			req:           nil,
			msg:           "test error",
			args:          []any{slog.String("key", "value")},
			wantRequestID: false,
			wantSessionID: false,
		},
	} {
		t.Run(test.description, func(t *testing.T) {
			buf.Reset()
			Error(test.msg, test.req, test.args...)
			output := buf.String()

			if test.wantRequestID && !strings.Contains(output, "request_id=123") {
				t.Errorf("expected output to contain request_id=123, got: %s", output)
			}
			if test.wantSessionID && !strings.Contains(output, "session_id=456") {
				t.Errorf("expected output to contain session_id=456, got: %s", output)
			}
			if !test.wantRequestID && strings.Contains(output, "request_id") {
				t.Errorf("expected output to not contain request_id, got: %s", output)
			}
			if !strings.Contains(output, test.msg) {
				t.Errorf("expected output to contain message '%s', got: %s", test.msg, output)
			}
			if !strings.Contains(output, "key=value") {
				t.Errorf("expected output to contain key=value, got: %s", output)
			}
		})
	}
}

func TestDebug(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)
	defer slog.SetDefault(slog.Default())

	for _, test := range []struct {
		description   string
		req           *models.Request
		msg           string
		args          []any
		wantRequestID bool
		wantSessionID bool
	}{{
		description:   "with request",
		req:           &models.Request{ID: 789, SessionID: 101112},
		msg:           "test debug",
		args:          []any{slog.String("key", "value")},
		wantRequestID: true,
		wantSessionID: true,
	},
		{
			description:   "with nil request",
			req:           nil,
			msg:           "test debug",
			args:          []any{slog.String("key", "value")},
			wantRequestID: false,
			wantSessionID: false,
		},
	} {
		t.Run(test.description, func(t *testing.T) {
			buf.Reset()
			Debug(test.msg, test.req, test.args...)
			output := buf.String()

			if test.wantRequestID && !strings.Contains(output, "request_id=789") {
				t.Errorf("expected output to contain request_id=789, got: %s", output)
			}
			if test.wantSessionID && !strings.Contains(output, "session_id=101112") {
				t.Errorf("expected output to contain session_id=101112, got: %s", output)
			}
			if !test.wantRequestID && strings.Contains(output, "request_id") {
				t.Errorf("expected output to not contain request_id, got: %s", output)
			}
			if !strings.Contains(output, test.msg) {
				t.Errorf("expected output to contain message '%s', got: %s", test.msg, output)
			}
		})
	}
}

func TestInfo(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	slog.SetDefault(logger)
	defer slog.SetDefault(slog.Default())

	req := &models.Request{ID: 999, SessionID: 888}
	buf.Reset()
	Info("test info", req)
	output := buf.String()

	if !strings.Contains(output, "request_id=999") {
		t.Errorf("expected output to contain request_id=999, got: %s", output)
	}
	if !strings.Contains(output, "session_id=888") {
		t.Errorf("expected output to contain session_id=888, got: %s", output)
	}
	if !strings.Contains(output, "test info") {
		t.Errorf("expected output to contain message 'test info', got: %s", output)
	}
}

func TestWarn(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	slog.SetDefault(logger)
	defer slog.SetDefault(slog.Default())

	req := &models.Request{ID: 555, SessionID: 666}
	buf.Reset()
	Warn("test warn", req, slog.String("warning", "something"))
	output := buf.String()

	if !strings.Contains(output, "request_id=555") {
		t.Errorf("expected output to contain request_id=555, got: %s", output)
	}
	if !strings.Contains(output, "session_id=666") {
		t.Errorf("expected output to contain session_id=666, got: %s", output)
	}
	if !strings.Contains(output, "test warn") {
		t.Errorf("expected output to contain message 'test warn', got: %s", output)
	}
	if !strings.Contains(output, "warning=something") {
		t.Errorf("expected output to contain warning=something, got: %s", output)
	}
}

func TestErrorWithNilRequest(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	slog.SetDefault(logger)
	defer slog.SetDefault(slog.Default())

	buf.Reset()
	Error("nil request test", nil, slog.String("key", "value"))
	output := buf.String()

	if strings.Contains(output, "request_id") {
		t.Errorf("expected output to not contain request_id when req is nil, got: %s", output)
	}
	if strings.Contains(output, "session_id") {
		t.Errorf("expected output to not contain session_id when req is nil, got: %s", output)
	}
	if !strings.Contains(output, "nil request test") {
		t.Errorf("expected output to contain message 'nil request test', got: %s", output)
	}
}
