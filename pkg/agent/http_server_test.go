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
package agent

import (
	"fmt"
	"io"
	"lophiid/backend_service"
	"lophiid/pkg/backend"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCatchAllOk(t *testing.T) {
	var port int64 = 8888
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	expectedResponseBody := []byte("hello123")
	expectedHeader := "Content-Type"
	expectedHeaderVal := "foo/bar"

	// The fake response from the RPC server.
	pr := &backend_service.HandleProbeResponse{
		Response: &backend_service.HttpResponse{
			Body: expectedResponseBody,
			Header: []*backend_service.KeyValue{
				{
					Key:   expectedHeader,
					Value: expectedHeaderVal,
				},
			},
		},
	}

	bc := backend.FakeBackendClient{
		HandleProbeReturnResponse: pr,
	}

	// Call the actual code.
	s := NewHttpServer(&bc, listenAddr, "127.0.0.1")
	req := httptest.NewRequest(http.MethodGet, "/test?aa=bb&cc=dd", nil)
	w := httptest.NewRecorder()
	s.catchAll(w, req)

	res := w.Result()

	// Check the request body
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("reading response body: %s", err)
	}

	if string(data) != string(expectedResponseBody) {
		t.Errorf("body %s != %s", data, expectedResponseBody)
	}
	// Check the header.
	if len(res.Header) != 1 {
		t.Fatalf("res.Header length is %d", len(res.Header))
	}

	hv := res.Header.Get(expectedHeader)
	if hv != expectedHeaderVal {
		t.Errorf("header value '%s' != '%s'", hv, expectedHeaderVal)
	}

	// Check whether struct values were moved properly.
	if bc.CapturedProbeRequest.Request.GetParsedUrl().Port != port {
		t.Errorf("port %d != %d", bc.CapturedProbeRequest.Request.GetParsedUrl().Port, port)
	}
	expectedQueryLen := 2
	actualQueryLen := len(bc.CapturedProbeRequest.Request.GetParsedUrl().GetQuery())
	if actualQueryLen != expectedQueryLen {
		t.Errorf("len Query %d != %d", actualQueryLen, expectedQueryLen)
	}
}

func TestCatchAllResourceExhausted(t *testing.T) {
	listenAddr := "127.0.0.1:8888"

	// Create a backend client that returns a ResourceExhausted error
	bc := backend.FakeBackendClient{
		HandleProbeReturnError: status.Error(codes.ResourceExhausted, "resource exhausted"),
	}

	// Create server and test request
	s := NewHttpServer(&bc, listenAddr, "127.0.0.1")
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	s.catchAll(w, req)

	res := w.Result()
	defer res.Body.Close()

	// Verify status code is 404
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("expected status code %d, got %d", http.StatusNotFound, res.StatusCode)
	}

	// Verify response body
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("reading response body: %s", err)
	}

	expectedBody := "<html></html>"
	if string(data) != expectedBody {
		t.Errorf("expected body %q, got %q", expectedBody, string(data))
	}
}
