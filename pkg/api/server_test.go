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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"gopkg.in/yaml.v3"
)

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
			description: "Insert fail",
			content: models.Content{
				Name:        "Foo",
				ContentType: "text/html",
				Server:      "Apache",
				Data:        []byte("<b>Ai</b>"),
			},
			status:            ResultError,
			statusMsgContains: "unable to insert",
			dbErr:             errors.New("fail"),
			scriptErr:         nil,
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

func TestGetSingleContent(t *testing.T) {
	for _, test := range []struct {
		description       string
		queryString       string
		expectedData      []byte
		statusMsgContains string
		status            string
		err               error
	}{
		{
			description:       "Runs OK",
			queryString:       "/?id=42",
			expectedData:      []byte("test123"),
			statusMsgContains: "",
			status:            ResultSuccess,
			err:               nil,
		},
		{
			description:       "Invalid ID",
			queryString:       "/?id=INVALID",
			expectedData:      []byte(""),
			statusMsgContains: "invalid syntax",
			status:            ResultError,
			err:               nil,
		},
		{
			description:       "Database error",
			queryString:       "/?id=42",
			expectedData:      []byte(""),
			statusMsgContains: "oops",
			status:            ResultError,
			err:               errors.New("oops"),
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			fd := database.FakeDatabaseClient{
				ContentsToReturn: map[int64]models.Content{
					42: models.Content{
						Data: test.expectedData,
					},
				},
				ErrorToReturn: test.err,
			}
			fakeJrunner := javascript.FakeJavascriptRunner{}
			s := NewApiServer(&fd, &fakeJrunner, "apiKey")

			req := httptest.NewRequest(http.MethodGet, test.queryString, nil)
			w := httptest.NewRecorder()
			s.HandleGetSingleContent(w, req)
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

			if pdata.Status != test.status {
				t.Errorf("status %s expected, got %s", test.status, pdata.Status)
			}

			// If the result is OK then we expect 1 Content to have returned and
			// subsequently check if the expected content string is present.
			if pdata.Status == ResultSuccess {
				if len(pdata.Data) != 1 {
					t.Fatalf("unexpected contents len %d", len(pdata.Data))
				}
				content := pdata.Data[0]
				if !bytes.Contains(content.Data, test.expectedData) {
					t.Errorf("expected \"%s\" to contain \"%s\"", content.Data, test.expectedData)
				}
			}

			if test.statusMsgContains != "" && !strings.Contains(pdata.Message, test.statusMsgContains) {
				t.Errorf("%s does not contain %s", pdata.Message, test.statusMsgContains)
			}

		})
	}
}

func TestGetSingleContentRule(t *testing.T) {
	for _, test := range []struct {
		description string
		queryString string
		uri         string
		contentId   int64
		status      string
		err         error
	}{
		{
			description: "fetch successful",
			queryString: "/contentrule/get?id=42",
			uri:         "/this/path",
			contentId:   42,
			status:      ResultSuccess,
			err:         nil,
		},
		{
			description: "fetch fails",
			queryString: "/contentrule/get?id=42",
			uri:         "/this/path",
			contentId:   42,
			status:      ResultError,
			err:         errors.New("fail fail"),
		},

		{
			description: "id parsing fails",
			queryString: "/contentrule/get?id=FAIL",
			uri:         "/this/path",
			contentId:   42,
			status:      ResultError,
			err:         nil,
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			fd := database.FakeDatabaseClient{
				ContentRulesToReturn: []models.ContentRule{
					{
						Uri:       test.uri,
						ContentID: test.contentId,
					},
				},
				ErrorToReturn: test.err,
			}

			fakeJrunner := javascript.FakeJavascriptRunner{}
			s := NewApiServer(&fd, &fakeJrunner, "apiKey")

			req := httptest.NewRequest(http.MethodGet, test.queryString, nil)
			w := httptest.NewRecorder()
			s.HandleGetSingleContentRule(w, req)
			res := w.Result()

			// Check the request body
			defer res.Body.Close()
			data, err := io.ReadAll(res.Body)
			if err != nil {
				t.Errorf("reading response body: %s", err)
			}

			pdata := HttpContentRuleResult{}
			if err = json.Unmarshal(data, &pdata); err != nil {
				t.Errorf("error parsing response: %s (%s)", err, string(data))
			}

			if pdata.Status != test.status {
				t.Errorf("status %s expected, got %s", test.status, pdata.Status)
			}

			if pdata.Status == ResultSuccess {
				dataLen := len(pdata.Data)
				if dataLen != 1 {
					t.Fatalf("expected 1 result but got %d", dataLen)
				}
				cr := pdata.Data[0]
				if cr.Uri != test.uri {
					t.Errorf("expected path %s, got %s", test.uri, cr.Uri)
				}
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
