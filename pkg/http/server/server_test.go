package http_server

import (
	"greyhole/backend_service"
	"greyhole/pkg/client"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCatchAllOk(t *testing.T) {
	var port int64 = 8888

	expectedResponseBody := "hello123"
	pr := &backend_service.HandleProbeResponse{
		Response: &backend_service.HttpResponse{
			Body: expectedResponseBody,
		},
	}

	bc := client.FakeBackendClient{
		HandleProbeReturnResponse: pr,
	}

	s := NewHttpServer(&bc, port)

	req := httptest.NewRequest(http.MethodGet, "/test?aa=bb&cc=dd", nil)
	w := httptest.NewRecorder()
	s.catchAll(w, req)

	res := w.Result()
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("reading response body: %s", err)
	}

	if string(data) != expectedResponseBody {
		t.Errorf("body %s != %s", data, expectedResponseBody)
	}

	if bc.CapturedProbeRequest.Request.GetParsedUrl().Port != port {
		t.Errorf("port %d != %d", bc.CapturedProbeRequest.Request.GetParsedUrl().Port, port)
	}
	expectedQueryLen := 2
	actualQueryLen := len(bc.CapturedProbeRequest.Request.GetParsedUrl().GetQuery())
	if actualQueryLen != expectedQueryLen {
		t.Errorf("len Query %d != %d", actualQueryLen, expectedQueryLen)
	}
}
