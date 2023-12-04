package api

import (
	"encoding/json"
	"errors"
	"io"
	"loophid/pkg/database"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUpsertSingleContent(t *testing.T) {
	for _, test := range []struct {
		description       string
		queryString       string
		status            string
		statusMsgContains string
		statusCode        int
		err               error
	}{
		{
			description:       "Insert OK",
			queryString:       "/?name=foo&content_type=text&server=Apache",
			status:            ResultSuccess,
			statusMsgContains: "Added",
			err:               nil,
		},
		{
			description:       "Updated OK",
			queryString:       "/?id=2&name=foo&content_type=text&server=Apache",
			status:            ResultSuccess,
			statusMsgContains: "Updated",
			err:               nil,
		},
		{
			description:       "Insert fails with error",
			queryString:       "/?name=foo&content_type=text&server=Apache",
			statusMsgContains: "fail",
			status:            ResultError,
			err:               errors.New("fail"),
		},
		{
			description:       "Update fails with error",
			queryString:       "/?id=2&name=foo&content_type=text&server=Apache",
			statusMsgContains: "fail",
			status:            ResultError,
			err:               errors.New("fail"),
		},
		{
			description:       "Update fails on ID",
			queryString:       "/?id=FAIL&name=foo&content_type=text&server=Apache",
			statusMsgContains: "Unable to parse",
			status:            ResultError,
			err:               nil,
		},
		{
			description:       "Missing parameters",
			queryString:       "/?id=32",
			statusMsgContains: "parameters given",
			status:            ResultError,
			err:               nil,
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			fd := database.FakeDatabaseClient{
				ErrorToReturn: test.err,
			}
			s := NewApiServer(&fd)

			req := httptest.NewRequest(http.MethodGet, test.queryString, nil)
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
		contentString     string
		statusMsgContains string
		status            string
		err               error
	}{
		{
			description:       "Runs OK",
			queryString:       "/?id=42",
			contentString:     "test123",
			statusMsgContains: "",
			status:            ResultSuccess,
			err:               nil,
		},
		{
			description:       "Invalid ID",
			queryString:       "/?id=INVALID",
			contentString:     "",
			statusMsgContains: "invalid syntax",
			status:            ResultError,
			err:               nil,
		},
		{
			description:       "Database error",
			queryString:       "/?id=42",
			contentString:     "",
			statusMsgContains: "oops",
			status:            ResultError,
			err:               errors.New("oops"),
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			fd := database.FakeDatabaseClient{
				ContentToReturn: database.Content{
					Content: test.contentString,
				},
				ErrorToReturn: test.err,
			}
			s := NewApiServer(&fd)

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
				if len(pdata.Contents) != 1 {
					t.Fatalf("unexpected contents len %d", len(pdata.Contents))
				}

				if !strings.Contains(pdata.Contents[0].Content, test.contentString) {
					t.Errorf("expected \"%s\" to contain \"%s\"", pdata.Contents[0].Content, test.contentString)
				}
			}

			if test.statusMsgContains != "" && !strings.Contains(pdata.Message, test.statusMsgContains) {
				t.Errorf("%s does not contain %s", string(data), test.contentString)
			}

		})
	}
}

func TestGetSingleContentRule(t *testing.T) {
	for _, test := range []struct {
		description string
		queryString string
		path        string
		contentId   int64
		status      string
		err         error
	}{
		{
			description: "fetch successful",
			queryString: "/contentrule/get?id=42",
			path:        "/this/path",
			contentId:   42,
			status:      ResultSuccess,
			err:         nil,
		},
		{
			description: "fetch fails",
			queryString: "/contentrule/get?id=42",
			path:        "/this/path",
			contentId:   42,
			status:      ResultError,
			err:         errors.New("fail fail"),
		},

		{
			description: "id parsing fails",
			queryString: "/contentrule/get?id=FAIL",
			path:        "/this/path",
			contentId:   42,
			status:      ResultError,
			err:         nil,
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			fd := database.FakeDatabaseClient{
				ContentRuleToReturn: database.ContentRule{
					Path:      test.path,
					ContentID: test.contentId,
				},
				ErrorToReturn: test.err,
			}
			s := NewApiServer(&fd)

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
				if len(pdata.ContentRules) != 1 {
					t.Fatalf("expected 1 result but got %d", len(pdata.ContentRules))
				}

				cr := pdata.ContentRules[0]
				if cr.Path != test.path {
					t.Errorf("expected path %s, got %s", test.path, cr.Path)

				}
			}
		})
	}
}
