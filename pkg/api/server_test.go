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
		description           string
		queryString           string
		status                string
		statusMessageContains string
		statusCode            int
		err                   error
	}{
		{
			description:           "Insert OK",
			queryString:           "/?name=foo&content_type=text&server=Apache",
			status:                "OK",
			statusMessageContains: "Added",
			statusCode:            200,
			err:                   nil,
		},
		{
			description:           "Updated OK",
			queryString:           "/?id=2&name=foo&content_type=text&server=Apache",
			status:                "OK",
			statusMessageContains: "Updated",
			statusCode:            200,
			err:                   nil,
		},
		{
			description:           "Insert fails with error",
			queryString:           "/?name=foo&content_type=text&server=Apache",
			statusMessageContains: "fail",
			status:                "NOK",
			statusCode:            200,
			err:                   errors.New("fail"),
		},
		{
			description:           "Update fails with error",
			queryString:           "/?id=2&name=foo&content_type=text&server=Apache",
			statusMessageContains: "fail",
			status:                "NOK",
			statusCode:            200,
			err:                   errors.New("fail"),
		},
		{
			description:           "Update fails on ID",
			queryString:           "/?id=FAIL&name=foo&content_type=text&server=Apache",
			statusMessageContains: "Unable to parse",
			status:                "NOK",
			statusCode:            200,
			err:                   nil,
		},
		{
			description:           "Missing parameters",
			queryString:           "/?id=32",
			statusMessageContains: "parameters given",
			status:                "NOK",
			statusCode:            200,
			err:                   nil,
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

			pdata := HttpResult{}
			if err = json.Unmarshal(data, &pdata); err != nil {
				t.Errorf("error parsing response: %s (%s)", err, string(data))
			}

			if pdata.Status != test.status {
				t.Errorf("status %s expected, got %s", test.status, pdata.Status)
			}
			if !strings.Contains(pdata.Message, test.statusMessageContains) {
				t.Errorf("expected \"%s \"in status message %s", test.statusMessageContains, pdata.Message)
			}
		})
	}
}

func TestGetSingleContent(t *testing.T) {
	for _, test := range []struct {
		description   string
		queryString   string
		contentString string
		statusCode    int
		err           error
	}{
		{
			description:   "Runs OK",
			queryString:   "/?id=42",
			contentString: "test123",
			statusCode:    200,
			err:           nil,
		},
		{
			description:   "Invalid ID",
			queryString:   "/?id=INVALID",
			contentString: "invalid syntax",
			statusCode:    500,
			err:           nil,
		},
		{
			description:   "Database error",
			queryString:   "/?id=42",
			contentString: "oops",
			statusCode:    500,
			err:           errors.New("oops"),
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

			if !strings.Contains(string(data), test.contentString) {
				t.Errorf("%s does not contain %s", string(data), test.contentString)
			}

			if res.StatusCode != test.statusCode {
				t.Errorf("status code %d expected, got %d", test.statusCode, res.StatusCode)
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
		statusCode  int
		err         error
	}{
		{
			description: "fetch successful",
			queryString: "/contentrule/get?id=42",
			path:        "/this/path",
			contentId:   42,
			statusCode:  200,
			err:         nil,
		},
		{
			description: "fetch fails",
			queryString: "/contentrule/get?id=42",
			path:        "/this/path",
			contentId:   42,
			statusCode:  500,
			err:         errors.New("fail fail"),
		},

		{
			description: "id parsing fails",
			queryString: "/contentrule/get?id=FAIL",
			path:        "/this/path",
			contentId:   42,
			statusCode:  500,
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

			if res.StatusCode != test.statusCode {
				t.Errorf("status code %d expected, got %d", test.statusCode, res.StatusCode)
			}

			if res.StatusCode != 500 && !strings.Contains(string(data), test.path) {
				t.Errorf("%s does not contain %s", string(data), test.path)
			}
		})
	}
}
