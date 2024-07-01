package ratelimit

import (
	"errors"
	"fmt"
	"log/slog"
	"loophid/pkg/database"
	"sync"
	"time"
)

var (
	ErrBucketLimitExceeded = errors.New("bucket limit exceeded")
	ErrWindowLimitExceeded = errors.New("window limit exceeded")
)

type RateLimiter interface {
	AllowRequest(req *database.Request) (bool, error)
}

// WindowRateLimiter can be used to limit requests per HoneypotIP, SourceIP and Uri
// combination.  If BucketDuration is set to 1 minute and RateWindow is set to
// one hour than:
//
//	The ratelimiter will only allow MaxRequestPerBucket requests per minute
//	The ratelimiter will only allow MaxRequestsPerWindow per the entire hour
//
// When any of these limits are met than the AllowRequest() method will return
// false.
//
// Requires Start() to be called before usage.
type WindowRateLimiter struct {
	MaxRequestsPerWindow int
	MaxRequestPerBucket  int
	RateWindow           time.Duration
	BucketDuration       time.Duration
	NumberBuckets        int
	RateBuckets          map[string][]int
	Metrics              *RatelimiterMetrics
	mu                   sync.Mutex
	bgChan               chan bool
}

func NewWindowRateLimiter(rateWindow time.Duration, bucketDuration time.Duration, maxRequestsPerWindow int, maxRequestPerBucket int, metrics *RatelimiterMetrics) *WindowRateLimiter {
	slog.Info("Creating ratelimiter", slog.String("window_size", rateWindow.String()), slog.String("bucket_size", bucketDuration.String()))
	return &WindowRateLimiter{
		BucketDuration:       bucketDuration,
		MaxRequestPerBucket:  maxRequestPerBucket,
		MaxRequestsPerWindow: maxRequestsPerWindow,
		RateWindow:           rateWindow,
		RateBuckets:          make(map[string][]int),
		NumberBuckets:        int(rateWindow / bucketDuration),
		Metrics:              metrics,
	}
}

func (r *WindowRateLimiter) Start() {
	ticker := time.NewTicker(r.BucketDuration)
	go func() {
		for {
			select {
			case <-r.bgChan:
				ticker.Stop()
				slog.Info("RateLimiter stopped")
				return
			case <-ticker.C:
				r.Tick()
			}
		}
	}()
}

func (r *WindowRateLimiter) Stop() {
	slog.Info("Stopping ratelimiter")
	r.bgChan <- true
}

func GetSumOfWindow(window []int) int {
	ret := 0
	for _, v := range window {
		ret += v
	}
	return ret
}

// Tick is called every BucketDuration and will update the window with a new
// bucket while removing windows where all buckets are 0 (basically no traffic
// seen).
func (r *WindowRateLimiter) Tick() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for k := range r.RateBuckets {
		r.RateBuckets[k] = r.RateBuckets[k][1:]
		r.RateBuckets[k] = append(r.RateBuckets[k], 0)

		if GetSumOfWindow(r.RateBuckets[k]) == 0 {
			delete(r.RateBuckets, k)
		}
	}
	r.Metrics.rateBucketsGauge.Set(float64(len(r.RateBuckets)))
}

// AllowRequest will return true if a request is allowed because the total
// requests in a window or bucket is not exceeded. If a request is not allowed
// then an error is returned with the reason why.
// Requires that Start() has been called before usage.
func (r *WindowRateLimiter) AllowRequest(req *database.Request) (bool, error) {
	rKey := fmt.Sprintf("%s-%s-%s", req.HoneypotIP, req.SourceIP, req.Uri)

	r.mu.Lock()
	defer r.mu.Unlock()

	_, ok := r.RateBuckets[rKey]
	// If the key is not present then this IP has no recent requests logged so we
	// create the buckets.
	if !ok {
		r.RateBuckets[rKey] = make([]int, r.NumberBuckets)
		r.RateBuckets[rKey][r.NumberBuckets-1] = 1
		return true, nil
	}

	// Check if the bucket limit is not already exceeded.
	if r.RateBuckets[rKey][r.NumberBuckets-1] >= r.MaxRequestPerBucket {
		return false, ErrBucketLimitExceeded
	}

	// Check how many requests there have been in this window.
	if GetSumOfWindow(r.RateBuckets[rKey]) >= r.MaxRequestsPerWindow {
		return false, ErrWindowLimitExceeded
	}

	r.RateBuckets[rKey][r.NumberBuckets-1] += 1

	return true, nil
}

type FakeRateLimiter struct {
	BoolToReturn  bool
	ErrorToReturn error
}

func (f *FakeRateLimiter) AllowRequest(*database.Request) (bool, error) {
	return f.BoolToReturn, f.ErrorToReturn
}
