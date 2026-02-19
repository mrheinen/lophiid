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
	"errors"
	"fmt"
	"io"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/javascript"
	"lophiid/pkg/util/constants"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestGetQueryParameters(t *testing.T) {
	for _, test := range []struct {
		description    string
		queryString    string
		wantOffset     int64
		wantLimit      int64
		wantQuery      string
		wantErr        bool
		errMsgContains string
	}{
		{
			description:    "missing offset and limit",
			queryString:    "",
			wantErr:        true,
			errMsgContains: "offset and limit must be provided",
		},
		{
			description:    "missing offset",
			queryString:    "limit=10",
			wantErr:        true,
			errMsgContains: "offset and limit must be provided",
		},
		{
			description:    "missing limit",
			queryString:    "offset=0",
			wantErr:        true,
			errMsgContains: "offset and limit must be provided",
		},
		{
			description:    "invalid offset",
			queryString:    "offset=abc&limit=10",
			wantErr:        true,
			errMsgContains: "invalid offset",
		},
		{
			description:    "invalid limit",
			queryString:    "offset=0&limit=abc",
			wantErr:        true,
			errMsgContains: "invalid limit",
		},
		{
			description:    "limit is zero",
			queryString:    "offset=0&limit=0",
			wantErr:        true,
			errMsgContains: "limit must be greater than 0",
		},
		{
			description:    "limit is negative",
			queryString:    "offset=0&limit=-5",
			wantErr:        true,
			errMsgContains: "limit must be greater than 0",
		},
		{
			description:    "negative offset",
			queryString:    "offset=-1&limit=10",
			wantErr:        true,
			errMsgContains: "offset must be positive",
		},
		{
			description: "valid without query",
			queryString: "offset=0&limit=10",
			wantOffset:  0,
			wantLimit:   10,
			wantQuery:   "",
			wantErr:     false,
		},
		{
			description: "valid with query",
			queryString: "offset=5&limit=20&q=name%3Dfoo",
			wantOffset:  5,
			wantLimit:   20,
			wantQuery:   "name=foo",
			wantErr:     false,
		},
	} {
		t.Run(test.description, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test?"+test.queryString, nil)
			offset, limit, query, err := GetQueryParameters(req)

			if test.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.errMsgContains)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.wantOffset, offset)
				assert.Equal(t, test.wantLimit, limit)
				assert.Equal(t, test.wantQuery, query)
			}
		})
	}
}

func TestUpsertSingleContent(t *testing.T) {
	for _, test := range []struct {
		description       string
		content           models.Content
		status            string
		statusMsgContains string
		statusCode        int
		dbErr             error
		scriptErr         error
	}{
		{
			description: "Insert OK",
			content: models.Content{
				Name:        "Foo",
				ContentType: "text/html",
				Server:      "Apache",
				Headers:     pgtype.FlatArray[string]{"Foo: bar"},
				Data:        []byte("<b>Ai</b>"),
			},
			status:            ResultSuccess,
			statusMsgContains: "Added",
			dbErr:             nil,
			scriptErr:         nil,
		},
		{
			description: "Insert fails on header",
			content: models.Content{
				Name:        "Foo",
				ContentType: "text/html",
				Server:      "Apache",
				Headers:     pgtype.FlatArray[string]{"Notavalidheader"},
				Data:        []byte("<b>Ai</b>"),
			},
			status:            ResultError,
			statusMsgContains: "Notavalidheader",
			dbErr:             nil,
			scriptErr:         nil,
		},
		{
			description: "Insert fails on header name",
			content: models.Content{
				Name:        "Foo",
				ContentType: "text/html",
				Server:      "Apache",
				Headers:     pgtype.FlatArray[string]{"y766***&: bar"},
				Data:        []byte("<b>Ai</b>"),
			},
			status:            ResultError,
			statusMsgContains: "Invalid header name",
			dbErr:             nil,
			scriptErr:         nil,
		},

		{
			description: "Insert OK script",
			content: models.Content{
				Name:        "Foo",
				ContentType: "text/html",
				Server:      "Apache",
				Data:        []byte(""),
				Script:      "1+1",
			},
			status:            ResultSuccess,
			statusMsgContains: "Added",
			dbErr:             nil,
			scriptErr:         nil,
		},
		{
			description: "Insert OK, script not",
			content: models.Content{
				Name:        "Foo",
				ContentType: "text/html",
				Server:      "Apache",
				Data:        []byte(""),
				Script:      "1+1",
			},
			status:            ResultError,
			statusMsgContains: "patrick",
			dbErr:             nil,
			scriptErr:         errors.New("this is patrick"),
		},
		{
			description: "Updated OK",
			content: models.Content{
				ID:          42,
				Name:        "Foo",
				ContentType: "text/html",
				Server:      "Apache",
				Data:        []byte("<b>Ai</b>"),
			},
			status:            ResultSuccess,
			statusMsgContains: "Updated",
			dbErr:             nil,
			scriptErr:         nil,
		},
		{
			description: "Updated fail",
			content: models.Content{
				ID:          42,
				Name:        "Foo",
				ContentType: "text/html",
				Server:      "Apache",
				Data:        []byte("<b>Ai</b>"),
			},
			status:            ResultError,
			statusMsgContains: "unable to update",
			dbErr:             errors.New("fail"),
			scriptErr:         nil,
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			fd := database.FakeDatabaseClient{
				ErrorToReturn: test.dbErr,
			}
			fakeJrunner := javascript.FakeJavascriptRunner{
				StringToReturn: "OK",
				ErrorToReturn:  test.scriptErr,
			}
			s := NewApiServer(&fd, &fakeJrunner, "apikey")

			buf := new(bytes.Buffer)
			json.NewEncoder(buf).Encode(test.content)

			req := httptest.NewRequest(http.MethodPost, "/foo", strings.NewReader(buf.String()))
			w := httptest.NewRecorder()
			s.HandleUpsertSingleContent(w, req)
			res := w.Result()

			// Check the request body
			defer res.Body.Close()
			data, err := io.ReadAll(res.Body)
			if err != nil {
				t.Errorf("reading response body: %s", err)
			}

			pdata := HttpContentResult{}
			if err = json.Unmarshal(data, &pdata); err != nil {
				t.Errorf("error parsing response: %s (%s)", err, string(data))
			}

			if pdata.Status == ResultSuccess && test.content.ID > 0 && test.content.ID != pdata.Data[0].ID {
				t.Errorf("expected id %d, got %d", test.content.ID, pdata.Data[0].ID)
			}

			if pdata.Status != test.status {
				t.Errorf("status %s expected, got %s", test.status, pdata.Status)
			}
			if !strings.Contains(pdata.Message, test.statusMsgContains) {
				t.Errorf("expected \"%s \"in status message %s", test.statusMsgContains, pdata.Message)
			}
		})
	}
}

func TestExportApp(t *testing.T) {
	for _, test := range []struct {
		description        string
		appID              int
		app                models.Application
		contentRules       []models.ContentRule
		contents           map[int64]models.Content
		expectedStatus     string
		expectedNrApps     int
		expectedNrRules    int
		expectedNrContents int
	}{
		{
			description: "exports OK",
			appID:       42,
			app: models.Application{
				ID: 42,
			},
			contentRules: []models.ContentRule{
				{ContentID: 60},
				{ContentID: 61},
			},
			contents: map[int64]models.Content{
				60: {ID: 60},
				61: {ID: 61},
			},
			expectedStatus:     ResultSuccess,
			expectedNrApps:     1,
			expectedNrRules:    2,
			expectedNrContents: 2,
		},
		{
			description: "exports OK, duplicate rule",
			appID:       42,
			app: models.Application{
				ID: 42,
			},
			contentRules: []models.ContentRule{
				{ContentID: 60},
				{ContentID: 61},
				{ContentID: 61},
			},
			contents: map[int64]models.Content{
				60: {ID: 60},
				61: {ID: 61},
			},
			expectedStatus:     ResultSuccess,
			expectedNrApps:     1,
			expectedNrRules:    3,
			expectedNrContents: 2,
		},
		{
			description: "misses content rule, is fine",
			appID:       42,
			app: models.Application{
				ID: 42,
			},
			contentRules:       []models.ContentRule{},
			contents:           map[int64]models.Content{},
			expectedStatus:     ResultSuccess,
			expectedNrApps:     0,
			expectedNrRules:    0,
			expectedNrContents: 0,
		},
		{
			description: "misses content, not happy",
			appID:       42,
			app: models.Application{
				ID: 42,
			},
			contentRules: []models.ContentRule{
				{ContentID: 60},
				{ContentID: 61},
			},
			contents:           map[int64]models.Content{},
			expectedStatus:     ResultError,
			expectedNrApps:     0,
			expectedNrRules:    0,
			expectedNrContents: 0,
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			fd := database.FakeDatabaseClient{
				ApplicationToReturn:  test.app,
				ContentRulesToReturn: test.contentRules,
				ContentsToReturn:     test.contents,
			}

			s := NewApiServer(&fd, &javascript.FakeJavascriptRunner{}, "apiKey")

			formdata := url.Values{}
			formdata.Set("id", "42")

			req := httptest.NewRequest(http.MethodPost, "/foo", bytes.NewBufferString(formdata.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			s.ExportAppWithContentAndRule(w, req)
			res := w.Result()

			// Check the request body
			defer res.Body.Close()
			data, err := io.ReadAll(res.Body)
			if err != nil {
				t.Errorf("reading response body: %s", err)
			}

			type Export struct {
				Status  string
				Message string
				Data    AppYamlExport
			}

			pdata := Export{}
			if err = json.Unmarshal(data, &pdata); err != nil {
				t.Errorf("error parsing json response: %s (%s)", err, string(data))
			}

			ydata := AppExport{}
			if err = yaml.Unmarshal([]byte(pdata.Data.Yaml), &ydata); err != nil {
				t.Errorf("error parsing yaml response: %s (%s)", err, string(data))
			}

			if pdata.Status != test.expectedStatus {
				t.Errorf("status %s expected, got %s (%v)", test.expectedStatus, pdata.Status, pdata)
			}

			if test.expectedNrApps > 0 {
				if len(ydata.Rules) != test.expectedNrRules {
					t.Errorf("expected %d rules, got %d", test.expectedNrRules, len(ydata.Rules))

				}
			}
		})
	}
}

func TestImportAppOk(t *testing.T) {

	for _, test := range []struct {
		description    string
		expectedStatus string
		appExport      AppExport
	}{
		{
			description:    "exports OK",
			expectedStatus: ResultSuccess,
			appExport: AppExport{
				App: &models.Application{
					ID:      42,
					ExtUuid: "de71fafb-12e1-489e-aff7-b50ef7d1b7ef",
				},
				Rules: []models.ContentRule{
					{
						ExtUuid:     "94f65acf-2679-4cad-bfc3-10c628ee6a71",
						ContentUuid: "73fe055f-203c-4ff3-b87b-f372f58c70cf",
					},
				},
				Contents: []models.Content{
					{
						ExtUuid: "73fe055f-203c-4ff3-b87b-f372f58c70cf",
						ID:      55,
					},
				},
			},
		},
		{
			description:    "invalid App UUID",
			expectedStatus: ResultError,
			appExport: AppExport{
				App: &models.Application{
					ID:      42,
					ExtUuid: "OOOOOOOHLALA",
				},
				Rules: []models.ContentRule{
					{
						ExtUuid:     "94f65acf-2679-4cad-bfc3-10c628ee6a71",
						ContentUuid: "73fe055f-203c-4ff3-b87b-f372f58c70cf",
					},
				},
				Contents: []models.Content{
					{
						ID:      55,
						ExtUuid: "73fe055f-203c-4ff3-b87b-f372f58c70cf",
					},
				},
			},
		},
		{
			description:    "invalid Rule UUID",
			expectedStatus: ResultError,
			appExport: AppExport{
				App: &models.Application{
					ID:      42,
					ExtUuid: "94f65acf-2679-4cad-bfc3-10c628ee6a71",
				},
				Rules: []models.ContentRule{
					{
						ExtUuid:     "FAIL",
						ContentUuid: "73fe055f-203c-4ff3-b87b-f372f58c70cf",
					},
				},
				Contents: []models.Content{
					{
						ID:      55,
						ExtUuid: "73fe055f-203c-4ff3-b87b-f372f58c70cf",
					},
				},
			},
		},
		{
			description:    "invalid Rule ContentUUID",
			expectedStatus: ResultError,
			appExport: AppExport{
				App: &models.Application{
					ID:      42,
					ExtUuid: "94f65acf-2679-4cad-bfc3-10c628ee6a71",
				},
				Rules: []models.ContentRule{
					{
						ExtUuid:     "73fe055f-203c-4ff3-b87b-f372f58c70cf",
						ContentUuid: "POOOOL",
					},
				},
				Contents: []models.Content{
					{
						ID:      55,
						ExtUuid: "73fe055f-203c-4ff3-b87b-f372f58c70cf",
					},
				},
			},
		},
		{
			description:    "exports misses content",
			expectedStatus: ResultError,
			appExport: AppExport{
				App: &models.Application{
					ID:      42,
					ExtUuid: "de71fafb-12e1-489e-aff7-b50ef7d1b7ef",
				},
				Rules: []models.ContentRule{
					{
						ExtUuid:     "94f65acf-2679-4cad-bfc3-10c628ee6a71",
						ContentUuid: "73fe055f-203c-4ff3-b87b-f372f58c70cf",
					},
				},
				Contents: []models.Content{},
			},
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			fd := database.FakeDatabaseClient{
				ContentsToReturn: map[int64]models.Content{},
			}

			for _, ct := range test.appExport.Contents {
				fd.ContentsToReturn[ct.ID] = ct
			}

			s := NewApiServer(&fd, &javascript.FakeJavascriptRunner{}, "apiKey")
			yamlData, _ := yaml.Marshal(test.appExport)

			req := httptest.NewRequest(http.MethodPost, "/foo", bytes.NewBufferString(string(yamlData)))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			s.ImportAppWithContentAndRule(w, req)
			res := w.Result()

			// Check the request body
			defer res.Body.Close()
			data, err := io.ReadAll(res.Body)
			if err != nil {
				t.Errorf("reading response body: %s", err)
			}

			pdata := HttpResult{}
			if err = json.Unmarshal(data, &pdata); err != nil {
				t.Errorf("error parsing response: %s (%s)", err, string(data))
			}

			if pdata.Status != test.expectedStatus {
				t.Errorf("status %s expected, got %s (%v)", test.expectedStatus, pdata.Status, pdata)
			}
		})
	}

}

func TestHandleGetWhoisForIP(t *testing.T) {
	t.Run("No results found", func(t *testing.T) {
		fd := database.FakeDatabaseClient{
			WhoisModelsToReturn: []models.Whois{},
		}
		s := NewApiServer(&fd, nil, "apikey")

		req := httptest.NewRequest(http.MethodGet, "/whois?ip=1.2.3.4", nil)
		w := httptest.NewRecorder()
		s.HandleGetWhoisForIP(w, req)
		res := w.Result()

		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		if err != nil {
			t.Errorf("reading response body: %s", err)
		}

		var result HttpResult
		if err = json.Unmarshal(data, &result); err != nil {
			t.Errorf("error parsing response: %s (%s)", err, string(data))
		}

		if result.Status != ResultSuccess {
			t.Errorf("expected status %s, got %s", ResultSuccess, result.Status)
		}

		if result.Message != "No result" {
			t.Errorf("expected message 'No result', got %s", result.Message)
		}

		if result.Data != nil {
			t.Errorf("expected nil data, got %v", result.Data)
		}
	})
}

func TestHandleGetDescriptionForCmpHash(t *testing.T) {
	testCases := []struct {
		name           string
		hash           string
		descriptions   []models.RequestDescription
		dbError        error
		expectedStatus string
		expectedMsg    string
		expectData     bool
	}{
		{
			name:           "No results found",
			hash:           "abc123",
			descriptions:   []models.RequestDescription{},
			dbError:        nil,
			expectedStatus: ResultSuccess,
			expectedMsg:    "No result",
			expectData:     false,
		},
		{
			name: "Description found",
			hash: "abc123",
			descriptions: []models.RequestDescription{
				{
					CmpHash:             "abc123",
					AIDescription:       "Test description",
					AIVulnerabilityType: "Test vulnerability",
					AIApplication:       "Test app",
					AIMalicious:         "false",
					AIHasPayload:        "false",
					AICVE:               "CVE-2024-1234",
				},
			},
			dbError:        nil,
			expectedStatus: ResultSuccess,
			expectedMsg:    "",
			expectData:     true,
		},
		{
			name:           "Database error",
			hash:           "abc123",
			descriptions:   nil,
			dbError:        errors.New("database error"),
			expectedStatus: ResultError,
			expectedMsg:    "database error",
			expectData:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fd := database.FakeDatabaseClient{
				RequestDescriptionsToReturn: tc.descriptions,
				ErrorToReturn:               tc.dbError,
			}
			s := NewApiServer(&fd, nil, "apikey")

			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/description?cmp_hash=%s", tc.hash), nil)
			w := httptest.NewRecorder()
			s.HandleGetDescriptionForCmpHash(w, req)
			res := w.Result()

			defer res.Body.Close()
			data, err := io.ReadAll(res.Body)
			if err != nil {
				t.Errorf("reading response body: %s", err)
			}

			var result HttpResult
			if err = json.Unmarshal(data, &result); err != nil {
				t.Errorf("error parsing response: %s (%s)", err, string(data))
			}

			if result.Status != tc.expectedStatus {
				t.Errorf("expected status %s, got %s", tc.expectedStatus, result.Status)
			}

			if result.Message != tc.expectedMsg {
				t.Errorf("expected message %q, got %q", tc.expectedMsg, result.Message)
			}

			if tc.expectData {
				if result.Data == nil {
					t.Error("expected data to be present, got nil")
				}
				// Verify the returned description matches what we expect
				desc, ok := result.Data.(map[string]interface{})
				if !ok {
					t.Error("expected data to be a RequestDescription")
					return
				}
				if desc["cmp_hash"] != tc.descriptions[0].CmpHash {
					t.Errorf("expected cmp_hash %s, got %s", tc.descriptions[0].CmpHash, desc["cmp_hash"])
				}
			} else {
				if result.Data != nil {
					t.Errorf("expected no data, got %v", result.Data)
				}
			}
		})
	}
}

func TestHandleReviewDescription(t *testing.T) {

	t.Run("Incorrect status", func(t *testing.T) {
		fd := database.FakeDatabaseClient{
			RequestDescriptionsToReturn: []models.RequestDescription{},
			ErrorToReturn:               nil,
		}

		s := NewApiServer(&fd, nil, "apikey")

		formdata := url.Values{}
		formdata.Set("status", "WRONG")
		formdata.Set("hash", "ignored")

		req := httptest.NewRequest(http.MethodPost, "/foo", bytes.NewBufferString(formdata.Encode()))

		w := httptest.NewRecorder()
		s.HandleDescriptionReview(w, req)
		res := w.Result()

		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		if err != nil {
			t.Errorf("reading response body: %s", err)
		}

		var result HttpResult
		if err = json.Unmarshal(data, &result); err != nil {
			t.Errorf("error parsing response: %s (%s)", err, string(data))
		}

		if result.Status != ResultError {
			t.Errorf("expected status %s, got %s", ResultError, result.Status)
		}
	})

}

func TestCalculateContentLength(t *testing.T) {
	tests := []struct {
		name         string
		content      models.Content
		renderedData []byte
		wantErr      bool
		errMsg       string
	}{
		{
			name: "valid content length",
			content: models.Content{
				Headers: []string{"Content-Length: 5"},
			},
			renderedData: []byte("hello"),
			wantErr:      false,
		},
		{
			name: "invalid header format",
			content: models.Content{
				Headers: []string{"Content-Length"},
			},
			renderedData: []byte("hello"),
			wantErr:      true,
			errMsg:       "invalid header: Content-Length",
		},
		{
			name: "invalid content length value",
			content: models.Content{
				Headers: []string{"Content-Length: abc"},
			},
			renderedData: []byte("hello"),
			wantErr:      true,
			errMsg:       "invalid content length: abc",
		},
		{
			name: "content length mismatch",
			content: models.Content{
				Headers: []string{"Content-Length: 10"},
			},
			renderedData: []byte("hello"),
			wantErr:      true,
			errMsg:       "content-length should be: 5",
		},
		{
			name: "no content length header",
			content: models.Content{
				Headers: []string{"Content-Type: text/plain"},
			},
			renderedData: []byte("hello"),
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CalculateContentLength(tt.content, tt.renderedData)
			if (err != nil) != tt.wantErr {
				t.Errorf("CalculateContentLength() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && err.Error() != tt.errMsg {
				t.Errorf("CalculateContentLength() error message = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestHandleUpdateSingleDownload(t *testing.T) {
	tests := []struct {
		name           string
		input          models.Download
		dbError        error
		expectedCode   int
		expectedStatus string
	}{
		{
			name: "successful update",
			input: models.Download{
				ID:        1,
				RequestID: 100,
				Size:      1024,
				Port:      8080,
				IP:        "192.168.1.1",
			},
			dbError:        nil,
			expectedCode:   http.StatusOK,
			expectedStatus: ResultSuccess,
		},
		{
			name: "database error",
			input: models.Download{
				ID:        2,
				RequestID: 200,
			},
			dbError:        errors.New("database error"),
			expectedCode:   http.StatusOK,
			expectedStatus: ResultError,
		},
		{
			name:           "invalid json",
			input:          models.Download{},
			expectedCode:   http.StatusOK,
			expectedStatus: ResultError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fake database client
			fd := database.FakeDatabaseClient{
				ErrorToReturn: tt.dbError,
			}

			// Create API server with fake DB
			server := NewApiServer(&fd, nil, "aaa")

			// Create request body
			var body io.Reader
			if tt.name == "invalid json" {
				body = strings.NewReader("{invalid json}")
			} else {
				jsonData, err := json.Marshal(tt.input)
				if err != nil {
					t.Fatalf("failed to marshal input: %v", err)
				}
				body = bytes.NewReader(jsonData)
			}

			// Create request
			req := httptest.NewRequest(http.MethodPut, "/api/download", body)
			w := httptest.NewRecorder()

			// Call handler
			server.HandleUpdateSingleDownload(w, req)

			// Check response
			var resp struct {
				Status string `json:"status"`
			}
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if w.Code != tt.expectedCode {
				t.Errorf("expected status code %d, got %d", tt.expectedCode, w.Code)
			}
			if resp.Status != tt.expectedStatus {
				t.Errorf("expected status %s, got %s", tt.expectedStatus, resp.Status)
			}
		})
	}
}

func TestHandleDeleteAppDefaultProtected(t *testing.T) {
	fd := database.FakeDatabaseClient{}
	fakeJrunner := javascript.FakeJavascriptRunner{}
	s := NewApiServer(&fd, &fakeJrunner, "apikey")

	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/app/delete?id=%d", constants.DefaultUploadAppID), nil)
	w := httptest.NewRecorder()
	s.HandleDeleteApp(w, req)
	res := w.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	assert.NoError(t, err)

	pdata := HttpResult{}
	assert.NoError(t, json.Unmarshal(data, &pdata))
	assert.Equal(t, ResultError, pdata.Status)
	assert.Contains(t, pdata.Message, "cannot delete the default upload application")
}

func TestHandleDeleteRuleGroupDefaultProtected(t *testing.T) {
	fd := database.FakeDatabaseClient{}
	fakeJrunner := javascript.FakeJavascriptRunner{}
	s := NewApiServer(&fd, &fakeJrunner, "apikey")

	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/rulegroup/delete?id=%d", constants.DefaultRuleGroupID), nil)
	w := httptest.NewRecorder()
	s.HandleDeleteRuleGroup(w, req)
	res := w.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	assert.NoError(t, err)

	pdata := HttpResult{}
	assert.NoError(t, json.Unmarshal(data, &pdata))
	assert.Equal(t, ResultError, pdata.Status)
	assert.Contains(t, pdata.Message, "cannot delete the default rule group")
}

func TestHandleUpdateAppsForGroup(t *testing.T) {
	for _, test := range []struct {
		description       string
		body              string
		status            string
		statusMsgContains string
		dbErr             error
	}{
		{
			description:       "Success with apps",
			body:              `{"group_id": 1, "app_ids": [10, 20]}`,
			status:            ResultSuccess,
			statusMsgContains: "Updated apps",
			dbErr:             nil,
		},
		{
			description:       "Success with empty apps",
			body:              `{"group_id": 1, "app_ids": []}`,
			status:            ResultSuccess,
			statusMsgContains: "Updated apps",
			dbErr:             nil,
		},
		{
			description:       "Missing group_id",
			body:              `{"app_ids": [10]}`,
			status:            ResultError,
			statusMsgContains: "group_id is required",
			dbErr:             nil,
		},
		{
			description:       "Invalid JSON",
			body:              `{bad json`,
			status:            ResultError,
			statusMsgContains: "",
			dbErr:             nil,
		},
		{
			description:       "DB error on replace",
			body:              `{"group_id": 1, "app_ids": [10]}`,
			status:            ResultError,
			statusMsgContains: "failed to update apps",
			dbErr:             errors.New("db error"),
		},
	} {
		t.Run(test.description, func(t *testing.T) {
			fd := database.FakeDatabaseClient{
				ErrorToReturn: test.dbErr,
			}
			fakeJrunner := javascript.FakeJavascriptRunner{}
			s := NewApiServer(&fd, &fakeJrunner, "apikey")

			req := httptest.NewRequest(http.MethodPost, "/apppergroup/update", strings.NewReader(test.body))
			w := httptest.NewRecorder()
			s.HandleUpdateAppsForGroup(w, req)
			res := w.Result()

			defer res.Body.Close()
			data, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("reading response body: %s", err)
			}

			pdata := HttpResult{}
			if err = json.Unmarshal(data, &pdata); err != nil {
				t.Fatalf("error parsing response: %s (%s)", err, string(data))
			}

			if pdata.Status != test.status {
				t.Errorf("expected status %s, got %s (msg: %s)", test.status, pdata.Status, pdata.Message)
			}

			if test.statusMsgContains != "" && !strings.Contains(pdata.Message, test.statusMsgContains) {
				t.Errorf("expected message to contain %q, got %q", test.statusMsgContains, pdata.Message)
			}
		})
	}
}
