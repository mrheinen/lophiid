package http_server

import (
	"loophid/backend_service"
	"loophid/pkg/client"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCatchAllOk(t *testing.T) {
	var port int64 = 8888

	expectedResponseBody := "hello123"
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

	bc := client.FakeBackendClient{
		HandleProbeReturnResponse: pr,
	}

	// Call the actual code.
	s := NewHttpServer(&bc, port)
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

	if string(data) != expectedResponseBody {
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
