package agent

import (
	"bytes"
	"fmt"
	"io"
	"loophid/backend_service"
	"net/http"
	"testing"
	"time"
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

	agent := NewAgent(nil, []*HttpServer{}, client, nil /* p0fClient */, time.Minute, time.Minute, "1.1.1.1")

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

func TestDownloadToBufferContentType(t *testing.T) {
	backendRequest := backend_service.CommandDownloadFile{
		Url:        "http://127.0.0.1",
		HostHeader: "localhost",
		UserAgent:  "wget",
	}

	testBody := []byte("#!/bin/bash\nssss")
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

	agent := NewAgent(nil, []*HttpServer{}, client, nil /* p0frunner */, time.Minute, time.Minute, "1.1.1.1")

	resp, err := agent.DownloadToBuffer(&backendRequest)
	if err != nil {
		t.Errorf("expected no error, got %+v", err)
	}

	expectedMime := "text/x-shellscript"
	if resp.DetectedContentType != expectedMime {
		t.Errorf("expected mime %s, got %s", expectedMime, resp.DetectedContentType)
	}

}
