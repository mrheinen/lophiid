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
package ratelimit

import (
	"lophiid/pkg/database/models"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRateLimitOk(t *testing.T) {
	testRateWindow := time.Second * 5
	testBucketDuration := time.Second
	testMaxIpRequestsPerWindow := 4
	testMaxIpRequestPerBucket := 2

	req := models.Request{
		HoneypotIP: "1.1.1.1",
		SourceIP:   "2.2.2.2",
		Port:       31337,
		Uri:        "/aa",
	}
	reg := prometheus.NewRegistry()
	rMetrics := CreateRatelimiterMetrics(reg)

	// Test IP limiting
	r := NewWindowRateLimiter(WindowRateLimiterConfig{
		Name:                 "test_ip",
		RateWindow:           testRateWindow,
		BucketDuration:       testBucketDuration,
		MaxRequestsPerWindow: testMaxIpRequestsPerWindow,
		MaxRequestPerBucket:  testMaxIpRequestPerBucket,
		Metrics:              rMetrics,
		KeyFunc:              IPKeyFunc,
		BucketExceededErr:    ErrSessionIPBucketLimitExceeded,
		WindowExceededErr:    ErrSessionIPWindowLimitExceeded,
	})

	// Simulate multiple requests in the same bucket. It should
	// work OK twice and be rejected a third time due to the
	// MaxRequestPerBucket being set to 2.
	if isAllowed, err := r.AllowRequest(&req); !isAllowed {
		t.Errorf("not allowed, unexpected error %v", err)
	}
	if isAllowed, err := r.AllowRequest(&req); !isAllowed {
		t.Errorf("not allowed, unexpected error %v", err)
	}

	// This is the third one and needs to be rejected.
	isAllowed, err := r.AllowRequest(&req)
	if isAllowed {
		t.Errorf("request is allowed but it should be rejected")
	}

	if err != ErrSessionIPBucketLimitExceeded {
		t.Errorf("expected bucket exceeded, got unexpected error %v", err)
	}

	val := testutil.ToFloat64(rMetrics.rateLimiterRejects.WithLabelValues("bucket_" + r.Name()))
	if val != 1 {
		t.Errorf("expected bucket reject metric to be 1, got %v", val)
	}

	// Now we do a tick twice which resets the bucket limit. Therefore
	// the next request is allowed again.
	r.Tick()
	if isAllowed, err = r.AllowRequest(&req); !isAllowed {
		t.Errorf("unexpected error %v", err)
	}

	// Now the window limit is going to exceed though.
	isAllowed, err = r.AllowRequest(&req)
	if isAllowed {
		t.Errorf("request exceeds window limit and should be rejected")
	}

	if err != ErrSessionIPWindowLimitExceeded {
		t.Errorf("expected ErrWindowLimitExceeded but got %v", err)
	}

	val = testutil.ToFloat64(rMetrics.rateLimiterRejects.WithLabelValues("window_" + r.Name()))
	if val != 1 {
		t.Errorf("expected window reject metric to be 1, got %v", val)
	}

	// Now continue ticking until the window is empty and removed.
	r.Tick()
	r.Tick()
	r.Tick()
	r.Tick()
	r.Tick()

	if isAllowed, err := r.AllowRequest(&req); !isAllowed {
		t.Errorf("unexpected error %v", err)
	}
}

func TestAllowRequestForIP(t *testing.T) {
	tests := []struct {
		name          string
		req           *models.Request
		requestCount  int
		expectedAllow bool
		expectedError error
		setupRequests int  // number of requests to make before the actual test
		newBucket     bool // whether this should create a new bucket
	}{
		{
			name: "first request for IP creates bucket",
			req: &models.Request{
				HoneypotIP: "10.0.0.1",
				SourceIP:   "192.168.1.1",
				Port:       8080,
			},
			requestCount:  1,
			expectedAllow: true,
			expectedError: nil,
			newBucket:     true,
		},
		{
			name: "request within limits",
			req: &models.Request{
				HoneypotIP: "10.0.0.1",
				SourceIP:   "192.168.1.2",
				Port:       8080,
			},
			requestCount:  2,
			expectedAllow: true,
			expectedError: nil,
		},
		{
			name: "bucket limit exceeded",
			req: &models.Request{
				HoneypotIP: "10.0.0.1",
				SourceIP:   "192.168.1.3",
				Port:       8080,
			},
			requestCount:  3,
			setupRequests: 2, // make 2 requests first to reach the limit
			expectedAllow: false,
			expectedError: ErrSessionIPBucketLimitExceeded,
		},
		{
			name: "window limit exceeded",
			req: &models.Request{
				HoneypotIP: "10.0.0.1",
				SourceIP:   "192.168.1.4",
				Port:       8080,
			},
			requestCount:  5,
			setupRequests: 4, // make 4 requests first to reach the window limit
			expectedAllow: false,
			expectedError: ErrSessionIPWindowLimitExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			rMetrics := CreateRatelimiterMetrics(reg)

			// Create a new rate limiter for each test
			r := NewWindowRateLimiter(WindowRateLimiterConfig{
				Name:                 "test_ip",
				RateWindow:           time.Second * 5,
				BucketDuration:       time.Second,
				MaxRequestsPerWindow: 4,
				MaxRequestPerBucket:  2,
				Metrics:              rMetrics,
				KeyFunc:              IPKeyFunc,
				BucketExceededErr:    ErrSessionIPBucketLimitExceeded,
				WindowExceededErr:    ErrSessionIPWindowLimitExceeded,
			})

			// Perform setup requests if needed
			for i := 0; i < tt.setupRequests; i++ {
				r.AllowRequest(tt.req)
			}

			// Record initial bucket state if we're testing new bucket creation
			if tt.newBucket {
				ipRateKey, _ := IPKeyFunc(tt.req)
				if _, exists := r.rateBuckets[ipRateKey]; exists {
					t.Errorf("bucket should not exist before first request")
				}
			}

			// Perform the test request
			allowed, err := r.AllowRequest(tt.req)

			// Verify results
			if allowed != tt.expectedAllow {
				t.Errorf("AllowRequest() allowed = %v, want %v", allowed, tt.expectedAllow)
			}

			if err != tt.expectedError {
				t.Errorf("AllowRequest() error = %v, want %v", err, tt.expectedError)
			}

			// Verify bucket creation if applicable
			if tt.newBucket {
				ipRateKey, _ := IPKeyFunc(tt.req)
				if _, exists := r.rateBuckets[ipRateKey]; !exists {
					t.Errorf("bucket should exist after first request")
				}
			}

			// Verify metrics
			if tt.expectedAllow {
				val := testutil.ToFloat64(rMetrics.rateLimiterRejects.WithLabelValues("bucket_" + r.Name()))
				if val != 0 {
					t.Errorf("expected bucket reject metric to be 0, got %v", val)
				}
				val = testutil.ToFloat64(rMetrics.rateLimiterRejects.WithLabelValues("window_" + r.Name()))
				if val != 0 {
					t.Errorf("expected window reject metric to be 0, got %v", val)
				}
			} else {
				if tt.expectedError == ErrSessionIPBucketLimitExceeded {
					val := testutil.ToFloat64(rMetrics.rateLimiterRejects.WithLabelValues("bucket_" + r.Name()))
					if val != 1 {
						t.Errorf("expected bucket reject metric to be 1, got %v", val)
					}
				} else if tt.expectedError == ErrSessionIPWindowLimitExceeded {
					val := testutil.ToFloat64(rMetrics.rateLimiterRejects.WithLabelValues("window_" + r.Name()))
					if val != 1 {
						t.Errorf("expected window reject metric to be 1, got %v", val)
					}
				}
			}
		})
	}
}

func TestAllowRequestForURI(t *testing.T) {
	tests := []struct {
		name          string
		req           *models.Request
		requestCount  int
		expectedAllow bool
		expectedError error
		setupRequests int  // number of requests to make before the actual test
		newBucket     bool // whether this should create a new bucket
	}{
		{
			name: "first request for URI creates bucket",
			req: &models.Request{
				BaseHash: "hash1",
			},
			requestCount:  1,
			expectedAllow: true,
			expectedError: nil,
			newBucket:     true,
		},
		{
			name: "request within limits",
			req: &models.Request{
				BaseHash: "hash2",
			},
			requestCount:  2,
			expectedAllow: true,
			expectedError: nil,
		},
		{
			name: "bucket limit exceeded",
			req: &models.Request{
				BaseHash: "hash3",
			},
			requestCount:  3,
			setupRequests: 5, // make 5 requests first to reach the bucket limit
			expectedAllow: false,
			expectedError: ErrURIBucketLimitExceeded,
		},
		{
			name: "window limit exceeded",
			req: &models.Request{
				BaseHash: "hash4",
			},
			requestCount:  7,
			setupRequests: 6, // make 6 requests first to reach the window limit
			expectedAllow: false,
			expectedError: ErrURIWindowLimitExceeded,
		},
		{
			name: "window limit not exceeded for /",
			req: &models.Request{
				Uri:      "/",
				BaseHash: "hash4",
			},
			requestCount:  7,
			setupRequests: 6, // make 6 requests first to reach the window limit
			expectedAllow: true,
			expectedError: nil,
		},

		{
			name: "different URIs don't interfere",
			req: &models.Request{
				BaseHash: "hash5",
			},
			requestCount:  1,
			expectedAllow: true,
			expectedError: nil,
			newBucket:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new rate limiter for each test

			reg := prometheus.NewRegistry()
			rMetrics := CreateRatelimiterMetrics(reg)

			r := NewWindowRateLimiter(WindowRateLimiterConfig{
				Name:                 "test_uri",
				RateWindow:           time.Second * 5,
				BucketDuration:       time.Second,
				MaxRequestsPerWindow: 6,
				MaxRequestPerBucket:  5,
				Metrics:              rMetrics,
				KeyFunc:              URIKeyFunc,
				BucketExceededErr:    ErrURIBucketLimitExceeded,
				WindowExceededErr:    ErrURIWindowLimitExceeded,
			})

			// Perform setup requests if needed
			for i := 0; i < tt.setupRequests; i++ {
				if tt.name == "window limit exceeded" {
					// For window limit test, directly set up the buckets
					// Note: Since we are accessing internal fields for test setup, we need access to rateBuckets or simulate requests carefully.
					// Since we can't easily access rateBuckets in this test structure (it's unexported but in same package), we can use it.
					// But for simplicity let's just make requests.
					// However, simulating spreading across buckets with time sleeps is slow.
					// We can access r.rateBuckets if we are in the same package (ratelimit).
					// Yes, package is ratelimit.
					uriRateKey, _ := URIKeyFunc(tt.req)
					if i == 0 {
						r.rateBuckets[uriRateKey] = make([]int, r.numberBuckets)
					}
					// Spread requests across buckets to reach window limit
					r.rateBuckets[uriRateKey][i%r.numberBuckets] = 2
				} else {
					r.AllowRequest(tt.req)
				}
			}

			// Record initial bucket state if we're testing new bucket creation
			if tt.newBucket {
				uriRateKey, ok := URIKeyFunc(tt.req)
				if ok {
					if _, exists := r.rateBuckets[uriRateKey]; exists {
						t.Errorf("bucket should not exist before first request")
					}
				}
			}

			// Perform the test request
			allowed, err := r.AllowRequest(tt.req)

			// Verify results
			if allowed != tt.expectedAllow {
				t.Errorf("AllowRequest() allowed = %v, want %v", allowed, tt.expectedAllow)
			}

			if err != tt.expectedError {
				t.Errorf("AllowRequest() error = %v, want %v", err, tt.expectedError)
			}

			// Verify bucket creation if applicable
			if tt.newBucket {
				uriRateKey, ok := URIKeyFunc(tt.req)
				if ok {
					if _, exists := r.rateBuckets[uriRateKey]; !exists {
						t.Errorf("bucket should exist after first request")
					}
				}
			}

			// Verify metrics
			if tt.expectedAllow {
				val := testutil.ToFloat64(rMetrics.rateLimiterRejects.WithLabelValues("bucket_" + r.Name()))
				if val != 0 {
					t.Errorf("expected bucket reject metric to be 0, got %v", val)
				}
				val = testutil.ToFloat64(rMetrics.rateLimiterRejects.WithLabelValues("window_" + r.Name()))
				if val != 0 {
					t.Errorf("expected window reject metric to be 0, got %v", val)
				}
			} else {
				if tt.expectedError == ErrURIBucketLimitExceeded {
					val := testutil.ToFloat64(rMetrics.rateLimiterRejects.WithLabelValues("bucket_" + r.Name()))
					if val != 1 {
						t.Errorf("expected bucket reject metric to be 1, got %v", val)
					}
				} else if tt.expectedError == ErrURIWindowLimitExceeded {
					val := testutil.ToFloat64(rMetrics.rateLimiterRejects.WithLabelValues("window_" + r.Name()))
					if val != 1 {
						t.Errorf("expected window reject metric to be 1, got %v", val)
					}
				}
			}
		})
	}
}
