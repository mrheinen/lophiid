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
	"bytes"
	"errors"
	"io"
	"lophiid/backend_service"
	"lophiid/pkg/backend"
	"lophiid/pkg/util"
	"net/http"
	"testing"
	"time"

	"github.com/mrheinen/p0fclient"
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
		t.Errorf("expected %s, got %s", testBody, resp.Data)
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

func TestSendContext(t *testing.T) {

	for _, test := range []struct {
		description        string
		p0fResponse        *p0fclient.Response
		ipCacheValuesInit  map[string]bool
		ipCacheValuesAfter map[string]bool
		p0fError           error
		backendError       error
	}{
		{
			description: "runs ok",
			p0fResponse: &p0fclient.Response{},
			ipCacheValuesInit: map[string]bool{
				"1.1.1.1": false,
			},
			ipCacheValuesAfter: map[string]bool{
				"1.1.1.1": true,
			},
			p0fError:     nil,
			backendError: nil,
		},
		{
			description: "gets RPC error, does not modify cache",
			p0fResponse: &p0fclient.Response{},
			ipCacheValuesInit: map[string]bool{
				"1.1.1.1": false,
			},
			ipCacheValuesAfter: map[string]bool{
				"1.1.1.1": false,
			},
			p0fError:     nil,
			backendError: errors.New("boo"),
		},
		{
			description: "gets p0f error, does not modify cache",
			p0fResponse: &p0fclient.Response{},
			ipCacheValuesInit: map[string]bool{
				"1.1.1.1": false,
			},
			ipCacheValuesAfter: map[string]bool{
				"1.1.1.1": false,
			},
			p0fError:     errors.New("noo"),
			backendError: nil,
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			fakeP0fRunner := FakeP0fRunnerImpl{
				ResponseToReturn: test.p0fResponse,
				ErrorToReturn:    test.p0fError,
			}

			fakeBackendClient := backend.FakeBackendClient{
				SendSourceContextResponse: &backend_service.SendSourceContextResponse{},
				SendSourceContextError:    test.backendError,
			}

			ipCache := util.NewStringMapCache[bool]("test", time.Minute)
			for ip, wasSubmitted := range test.ipCacheValuesInit {
				ipCache.Store(ip, wasSubmitted)
			}

			agent := NewAgent(&fakeBackendClient, []*HttpServer{}, nil, &fakeP0fRunner, time.Minute, time.Minute, "1.1.1.1")
			agent.ipCache = ipCache

			agent.SendContext()

			for ip, wasSubmitted := range test.ipCacheValuesAfter {
				cacheEntry, err := ipCache.Get(ip)
				if err != nil {
					t.Errorf("expected no error, got %+v", err)
				}

				if *cacheEntry != wasSubmitted {
					t.Errorf("expected %v, got %v", wasSubmitted, cacheEntry)
				}
			}
		})

	}

}
