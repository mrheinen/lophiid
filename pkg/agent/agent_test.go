package agent

import (
	"bytes"
	"fmt"
	"io"
	"loophid/backend_service"
	http_server "loophid/pkg/http/server"
	"net/http"
	"testing"
)

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

func TestDownloadToBuffer(t *testing.T) {
	backendRequest := backend_service.CommandDownloadFile{
		Url:        "http://127.0.0.1",
		HostHeader: "localhost",
		UserAgent:  "wget",
	}

	testBody := []byte("hello")
	testContentType := "text/fake"

	client := NewTestClient(func(req *http.Request) *http.Response {
		hdrs := make(http.Header)
		hdrs.Add("Content-Type", testContentType)

		if req.Host != backendRequest.HostHeader {
			t.Errorf("expected host %s, but got %s", backendRequest.HostHeader, req.Host)
		}

		if req.Header.Get("User-Agent") != backendRequest.UserAgent {
			t.Errorf("expected %s, got %s", backendRequest.UserAgent, req.Header.Get("User-Agent"))
		}

		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBufferString(string(testBody))),
			// Must be set to non-nil value or it panics
			Header: hdrs,
		}
	})

	agent := NewAgent(nil, []*http_server.HttpServer{}, client, "1.1.1.1")

	resp, err := agent.DownloadToBuffer(&backendRequest)
	if err != nil {
		t.Errorf("expected no error, got %+v", err)
	}

	if resp.GetUrl() != backendRequest.GetUrl() {
		t.Errorf("expected %s, got %s", backendRequest.GetUrl(), resp.GetUrl())
	}

	if !bytes.Equal(testBody, resp.Data) {
		fmt.Printf("expected %s, got %s", testBody, resp.Data)
	}
}
