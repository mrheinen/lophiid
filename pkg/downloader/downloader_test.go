package downloader

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
)

func TestIsPrivate(t *testing.T) {
	for _, test := range []struct {
		description string
		ip          string
		isPrivate   bool
	}{
		{
			description: "is private",
			ip:          "127.0.0.1",
			isPrivate:   true,
		},
		{
			description: "is private",
			ip:          "192.168.1.1",
			isPrivate:   true,
		},
		{
			description: "is not private",
			ip:          "8.8.8.8",
			isPrivate:   false,
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			d := NewHTTPDownloader("/foo", &http.Client{})

			isRes := d.isPrivateIP(net.ParseIP(test.ip))
			if isRes != test.isPrivate {
				t.Errorf("expected isPrivate %t but got %t", test.isPrivate, isRes)
			}

		})
	}
}

func TestGetIPParts(t *testing.T) {
	for _, test := range []struct {
		description string
		url         string
		ip          net.IP
		host        string
		port        int
	}{
		{
			description: "resolve localhost ok",
			url:         "http://localhost:8000/aaaa",
			ip:          net.ParseIP("::1"),
			port:        8000,
			host:        "localhost",
		},
		{
			description: "resolve localhost without port",
			url:         "http://localhost/aaaa",
			ip:          net.ParseIP("::1"),
			port:        0,
			host:        "localhost",
		},
		{
			description: "handle ip with port",
			url:         "http://8.8.8.8:8888/aaaa",
			ip:          net.ParseIP("8.8.8.8"),
			port:        8888,
			host:        "8.8.8.8",
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			d := NewHTTPDownloader("/foo", &http.Client{})

			h, ip, port, _ := d.getIPForUrl(test.url)
			if h != test.host {
				t.Errorf("expected %s, got %s", test.host, h)
			}

			if ip.String() != test.ip.String() {
				t.Errorf("expected %s, got %s", test.ip, ip)
			}

			if port != test.port {
				t.Errorf("expected %d, got %d", test.port, port)
			}

		})
	}
}

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

func TestFromUrl(t *testing.T) {

	testBody := []byte("hello")
	testContentType := "text/fake"
	testHost := "example.org"

	client := NewTestClient(func(req *http.Request) *http.Response {
		hdrs := make(http.Header)
		hdrs.Add("Content-Type", testContentType)

		if req.Header.Get("Host") != testHost {
			t.Errorf("expected host %s, but got %s", req.Header.Get("Host"), testHost)
		}

		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBufferString(string(testBody))),
			// Must be set to non-nil value or it panics
			Header: hdrs,
		}
	})

	d := NewHTTPDownloader("/foo", client)
	testRequestID := int64(42)
	testUrl := fmt.Sprintf("http://%s", testHost)
	testTargetFile := fmt.Sprintf("/tmp/%d", rand.Intn(99999999))

	var wg sync.WaitGroup
	wg.Add(1)

	rDown, rData, err := d.FromUrl(testRequestID, testUrl, testTargetFile, &wg)
	if err != nil {
		t.Errorf("got error: %s", err)
	}

	if !bytes.Equal(rData, testBody) {
		t.Errorf("expected %s, got %s", testBody, rData)
	}

	if rDown.OriginalUrl != testUrl {
		t.Errorf("expected %s, got %s", testUrl, rDown.OriginalUrl)
	}
	if rDown.ContentType != testContentType {
		t.Errorf("expected %s, got %s", testContentType, rDown.ContentType)
	}

	os.Remove(testTargetFile)

}
