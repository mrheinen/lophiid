package cli

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

// TODO: move this http testing to a central spot.

// RoundTripFunc .
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip .
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

// NewTestClient returns *http.Client with Transport replaced to avoid making real calls
func NewTestClient(fn RoundTripFunc) *http.Client {
	return &http.Client{
		Transport: RoundTripFunc(fn),
	}
}

func TestFetchUrlToContent(t *testing.T) {

	testServerHeader := "Apache"
	testContentTypeHeader := "text/html"
	testExtraHeaderName := "X-Secret"
	testIgnoredHeaderName := "Date"
	httpResponseBody := "this is patrick"
	testTargetUrl := "http://example.org/aaa"
	testPrefix := "PREFIX"

	client := NewTestClient(func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Server":              []string{testServerHeader},
				"Content-Type":        []string{testContentTypeHeader},
				testExtraHeaderName:   []string{testExtraHeaderName},
				testIgnoredHeaderName: []string{"something"},
			},
			Body: io.NopCloser(bytes.NewBufferString(httpResponseBody)),
		}
	})

	ac := ApiCLI{
		httpClient: client,
	}

	content, err := ac.FetchUrlToContent(testPrefix, testTargetUrl)
	if err != nil {
		t.Errorf("unexpacted error: %s", err)
	}

	if content.ContentType != testContentTypeHeader {
		t.Errorf("expected content type %s, got %s", testContentTypeHeader, content.ContentType)
	}

	if content.Server != testServerHeader {
		t.Errorf("expected server %s, got %s", testServerHeader, content.Server)
	}

	if len(content.Headers) != 1 {
		t.Errorf("expected 1 header, got %d", len(content.Headers))
	}

}
