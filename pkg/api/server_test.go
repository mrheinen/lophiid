package api

import (
	"bytes"
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
		content           database.Content
		status            string
		statusMsgContains string
		statusCode        int
		err               error
	}{
		{
			description: "Insert OK",
			content: database.Content{
				Name:        "Foo",
				ContentType: "text/html",
				Server:      "Apache",
				Data:        []byte("<b>Ai</b>"),
			},
			status:            ResultSuccess,
			statusMsgContains: "Added",
			err:               nil,
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
			statusMsgContains: "Unable to insert",
			err:               errors.New("fail"),
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
			err:               nil,
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
			statusMsgContains: "Unable to update",
			err:               errors.New("fail"),
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			fd := database.FakeDatabaseClient{
				ErrorToReturn: test.err,
			}
			s := NewApiServer(&fd)

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
				ContentRulesToReturn: []database.ContentRule{
					{
						Path:      test.path,
						ContentID: test.contentId,
					},
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
				dataLen := len(pdata.Data)
				if dataLen != 1 {
					t.Fatalf("expected 1 result but got %d", dataLen)
				}
				cr := pdata.Data[0]
				if cr.Path != test.path {
					t.Errorf("expected path %s, got %s", test.path, cr.Path)
				}
			}
		})
	}
}
