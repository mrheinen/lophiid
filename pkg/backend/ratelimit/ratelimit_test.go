package ratelimit

import (
	"loophid/pkg/database"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRateLimitOk(t *testing.T) {
	testRateWindow := time.Second * 5
	testBucketDuration := time.Second
	testMaxRequestsPerWindow := 3
	testMaxRequestPerBucket := 2

	req := database.Request{
		HoneypotIP: "1.1.1.1",
		SourceIP:   "2.2.2.2",
	}
	reg := prometheus.NewRegistry()
	rMetrics := CreateRatelimiterMetrics(reg)
	r := NewRateLimiter(testRateWindow, testBucketDuration, testMaxRequestsPerWindow, testMaxRequestPerBucket, rMetrics)

	if testutil.ToFloat64(rMetrics.rateBucketsGauge) != 0 {
		t.Errorf("rateBucketsGauge should be 0 at the start")
	}

	// Simulate multiple requests in the same bucket. It should
	// work OK twice and be rejected a third time due to the
	// MaxRequestPerBucket being set to 2.
	if isAllowed, err := r.AllowRequest(&req); !isAllowed {
		t.Errorf("unexpected error %v", err)
	}
	if isAllowed, err := r.AllowRequest(&req); !isAllowed {
		t.Errorf("unexpected error %v", err)
	}

	// This is the third one and needs to be rejected.
	isAllowed, err := r.AllowRequest(&req)
	if isAllowed {
		t.Errorf("request is allowed but it should be rejected")
	}

	if err != ErrBucketLimitExceeded {
		t.Errorf("unexpected error %v", err)
	}

	// Now we do a tick which resets the bucket limit. Therefore
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

	if err != ErrWindowLimitExceeded {
		t.Errorf("expected ErrWindowLimitExceeded but got %v", err)
	}

	m := testutil.ToFloat64(rMetrics.rateBucketsGauge)
	if m != 1 {
		t.Errorf("rateBucketsGauge should be 1, is %f", m)
	}

	// Now continue ticking until the window is empty and removed.
	r.Tick()
	r.Tick()
	r.Tick()
	r.Tick()
	r.Tick()

	// Check if the RateBucket entry is indeed removed.
	m = testutil.ToFloat64(rMetrics.rateBucketsGauge)
	if m != 0 {
		t.Errorf("rateBucketsGauge should be 0 after reset")
	}

	if isAllowed, err := r.AllowRequest(&req); !isAllowed {
		t.Errorf("unexpected error %v", err)
	}
}
