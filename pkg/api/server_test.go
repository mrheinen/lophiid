package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"loophid/pkg/database"
	"loophid/pkg/javascript"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestUpsertSingleContent(t *testing.T) {
	for _, test := range []struct {
		description       string
		content           database.Content
		status            string
		statusMsgContains string
		statusCode        int
		dbErr             error
		scriptErr         error
	}{
		{
			description: "Insert OK",
			content: database.Content{
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
			content: database.Content{
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
			content: database.Content{
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
			content: database.Content{
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
			content: database.Content{
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
			content: database.Content{
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
			content: database.Content{
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
			content: database.Content{
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
				ContentsToReturn: map[int64]database.Content{
					42: database.Content{
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
				ContentRulesToReturn: []database.ContentRule{
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
		description    string
		appID          int
		app            database.Application
		contentRules   []database.ContentRule
		contents       map[int64]database.Content
		expectedStatus string
	}{
		{
			description: "exports OK",
			appID:       42,
			app: database.Application{
				ID: 42,
			},
			contentRules: []database.ContentRule{
				{ContentID: 60},
				{ContentID: 61},
			},
			contents: map[int64]database.Content{
				60: {ID: 60},
				61: {ID: 61},
			},
			expectedStatus: ResultSuccess,
		},
		{
			description: "misses content rule, is fine",
			appID:       42,
			app: database.Application{
				ID: 42,
			},
			contentRules:   []database.ContentRule{},
			contents:       map[int64]database.Content{},
			expectedStatus: ResultSuccess,
		},
		{
			description: "misses content, not happy",
			appID:       42,
			app: database.Application{
				ID: 42,
			},
			contentRules: []database.ContentRule{
				{ContentID: 60},
				{ContentID: 61},
			},
			contents:       map[int64]database.Content{},
			expectedStatus: ResultError,
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
