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
package cli

import (
	"bytes"
	"io"
	"lophiid/pkg/api"
	"lophiid/pkg/database/models"
	"net/http"
	"strings"
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
	testTargetUrl := "http://google.com/aaa"
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

	if strings.Contains(content.Description, "google.com") {
		t.Errorf("expected no reference to google.com in description")
	}

	if !strings.Contains(content.Description, "example.com") {
		t.Errorf("expected reference to example.com in description")
	}

	if len(content.Headers) != 1 {
		t.Errorf("expected 1 header, got %d", len(content.Headers))
	}

}

func TestFetchUrlAndCreateContentAndRule(t *testing.T) {
	fakeContentAPI := api.FakeApiClient[models.Content]{
		ErrorToReturn:     nil,
		DataModelToReturn: models.Content{ID: 42},
	}
	fakeContentRuleAPI := api.FakeApiClient[models.ContentRule]{
		ErrorToReturn:     nil,
		DataModelToReturn: models.ContentRule{},
	}

	apiCli := ApiCLI{
		contentAPI:     &fakeContentAPI,
		contentRuleAPI: &fakeContentRuleAPI,
	}

	err := apiCli.CreateContentAndRule(&models.Application{ID: 1}, []int64{80}, &models.Content{}, "http://example.org/?aa=bb")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if fakeContentRuleAPI.LastModelStored.Uri != "/?aa=bb" {
		t.Errorf("expected uri /?aa=bb, got %s", fakeContentRuleAPI.LastModelStored.Uri)
	}

	if fakeContentRuleAPI.LastModelStored.ContentID != 42 {
		t.Errorf("expected content id 42, got %d", fakeContentRuleAPI.LastModelStored.ContentID)
	}

	if fakeContentRuleAPI.LastModelStored.AppID != 1 {
		t.Errorf("expected content id 1, got %d", fakeContentRuleAPI.LastModelStored.AppID)
	}
}
