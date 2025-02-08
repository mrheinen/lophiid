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
package api

import (
	"bytes"
	"encoding/json"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestHandleUpsertSingleContentRule(t *testing.T) {
	for _, test := range []struct {
		description       string
		rule              models.ContentRule
		status            string
		statusMsgContains string
		statusCode        int
	}{
		{
			description: "Invalid port number",
			rule: models.ContentRule{
				ContentID: 1,
				AppID:     1,
				Uri:       "/test",
				Ports:     pgtype.FlatArray[int]{-1, 70000},
			},
			status:            ResultError,
			statusMsgContains: "Invalid port number",
		},
		{
			description: "Valid port numbers",
			rule: models.ContentRule{
				ContentID: 1,
				AppID:     1,
				Uri:       "/test",
				Ports:     pgtype.FlatArray[int]{80, 443},
			},
			status:            ResultSuccess,
			statusMsgContains: "",
		},
	} {
		t.Run(test.description, func(t *testing.T) {
			// Create a new API server with fake database
			fakeDb := &database.FakeDatabaseClient{
				ContentsToReturn: map[int64]models.Content{
					1: {ID: 1, ExtUuid: "test-uuid"},
				},
			}
			api := NewApiServer(fakeDb, nil, "test-key")

			// Create request body
			body, err := json.Marshal(test.rule)
			if err != nil {
				t.Fatalf("Failed to marshal request body: %v", err)
			}

			// Create request
			req := httptest.NewRequest(http.MethodPost, "/contentrule/upsert", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Call the handler
			api.HandleUpsertSingleContentRule(w, req)

			// Parse response
			var result HttpResult
			if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			// Check status
			if result.Status != test.status {
				t.Errorf("Expected status %s, got %s", test.status, result.Status)
			}

			// Check error message if expected
			if test.statusMsgContains != "" && !strings.Contains(result.Message, test.statusMsgContains) {
				t.Errorf("Expected message to contain %q, got %q", test.statusMsgContains, result.Message)
			}
		})
	}
}
