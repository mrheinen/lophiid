package api

import (
	"errors"
	"io"
	"loophid/pkg/database"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func getContentResponseForURL(queryStr string, content string, err error) *http.Response {
	fd := database.FakeDatabaseClient{
		ContentToReturn: database.Content{
			Content: content,
		},
		ErrorToReturn: err,
	}
	s := NewApiServer(&fd)

	req := httptest.NewRequest(http.MethodGet, queryStr, nil)
	w := httptest.NewRecorder()
	s.HandleGetSingleContent(w, req)
	return w.Result()
}

func TestGetSingleContentOK(t *testing.T) {
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
			res := getContentResponseForURL(test.queryString, test.contentString, test.err)
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
