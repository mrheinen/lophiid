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
	"errors"
	"fmt"
	"log/slog"
	"lophiid/pkg/database/models"
	"sync"
	"time"
)

var (
	ErrIPBucketLimitExceeded  = errors.New("IP bucket limit exceeded")
	ErrIPWindowLimitExceeded  = errors.New("IP window limit exceeded")
	ErrURIBucketLimitExceeded = errors.New("URI bucket limit exceeded")
	ErrURIWindowLimitExceeded = errors.New("URI window limit exceeded")
)

type RateLimiter interface {
	AllowRequest(req *models.Request) (bool, error)
	Name() string
}

// KeyFunc extracts a key for rate limiting from a request.
// The returned boolean indicates whether the request should be rate limited.
type KeyFunc func(req *models.Request) (string, bool)

func IPKeyFunc(req *models.Request) (string, bool) {
	return fmt.Sprintf("%s-%d-%s", req.HoneypotIP, req.Port, req.SourceIP), true
}

func URIKeyFunc(req *models.Request) (string, bool) {
	if req.Uri == "/" {
		return "", false
	}
	return req.BaseHash, true
}

// WindowRateLimiterConfig holds the configuration for WindowRateLimiter.
type WindowRateLimiterConfig struct {
	Name                 string
	RateWindow           time.Duration
	BucketDuration       time.Duration
	MaxRequestsPerWindow int
	MaxRequestPerBucket  int
	KeyFunc              KeyFunc
	BucketExceededErr    error
	WindowExceededErr    error
	Metrics              *RatelimiterMetrics
}

// WindowRateLimiter can be used to limit requests based on a key extracted from the request.
// If BucketDuration is set to 1 minute and RateWindow is set to one hour then:
//
//	The ratelimiter will only allow MaxRequestPerBucket requests per minute
//	The ratelimiter will only allow MaxRequestsPerWindow per the entire hour
//
// When any of these limits are met than the AllowRequest() method will return
// false.
//
// Requires Start() to be called before usage.
type WindowRateLimiter struct {
	name                 string
	maxRequestsPerWindow int
	maxRequestPerBucket  int
	metrics              *RatelimiterMetrics
	rateWindow           time.Duration
	bucketDuration       time.Duration
	numberBuckets        int
	rateBuckets          map[string][]int
	keyFunc              KeyFunc
	bucketExceededErr    error
	windowExceededErr    error
	mu                   sync.Mutex
	bgChan               chan bool
}

func NewWindowRateLimiter(cfg WindowRateLimiterConfig) *WindowRateLimiter {
	slog.Info("Creating ratelimiter", slog.String("name", cfg.Name), slog.String("window_size", cfg.RateWindow.String()), slog.String("bucket_size", cfg.BucketDuration.String()))
	return &WindowRateLimiter{
		name:                 cfg.Name,
		bucketDuration:       cfg.BucketDuration,
		maxRequestPerBucket:  cfg.MaxRequestPerBucket,
		maxRequestsPerWindow: cfg.MaxRequestsPerWindow,
		rateWindow:           cfg.RateWindow,
		rateBuckets:          make(map[string][]int),
		numberBuckets:        int(cfg.RateWindow / cfg.BucketDuration),
		keyFunc:              cfg.KeyFunc,
		metrics:              cfg.Metrics,
		bucketExceededErr:    cfg.BucketExceededErr,
		windowExceededErr:    cfg.WindowExceededErr,
		bgChan:               make(chan bool),
	}
}

func (r *WindowRateLimiter) Name() string {
	return r.name
}

func (r *WindowRateLimiter) Start() {
	ticker := time.NewTicker(r.bucketDuration)
	go func() {
		for {
			select {
			case <-r.bgChan:
				ticker.Stop()
				slog.Info("RateLimiter stopped", slog.String("name", r.name))
				return
			case <-ticker.C:
				r.Tick()
			}
		}
	}()
}

func (r *WindowRateLimiter) Stop() {
	slog.Info("Stopping ratelimiter", slog.String("name", r.name))
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
	for k := range r.rateBuckets {
		r.rateBuckets[k] = r.rateBuckets[k][1:]
		r.rateBuckets[k] = append(r.rateBuckets[k], 0)

		if GetSumOfWindow(r.rateBuckets[k]) == 0 {
			delete(r.rateBuckets, k)
		}
	}
	r.mu.Unlock()
}

// AllowRequest will return true if a request is allowed because the total
// requests in a window or bucket is not exceeded. If a request is not allowed
// then an error is returned with the reason why.
// Requires that Start() has been called before usage.
func (r *WindowRateLimiter) AllowRequest(req *models.Request) (bool, error) {
	if r == nil {
		return true, nil
	}

	if r.keyFunc == nil {
		return true, nil
	}

	rateKey, ok := r.keyFunc(req)
	if !ok {
		return true, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	_, exists := r.rateBuckets[rateKey]
	if !exists {
		r.rateBuckets[rateKey] = make([]int, r.numberBuckets)
		r.rateBuckets[rateKey][r.numberBuckets-1] = 1 // Count this request
		return true, nil
	}

	// Check how many requests there have been in this window.
	if GetSumOfWindow(r.rateBuckets[rateKey]) >= r.maxRequestsPerWindow {
		r.rateBuckets[rateKey][r.numberBuckets-1]++
		r.metrics.rateLimiterRejects.WithLabelValues("window_" + r.Name()).Add(1)
		return false, r.windowExceededErr
	}

	// Check if the bucket limit is not already exceeded.
	if r.rateBuckets[rateKey][r.numberBuckets-1] >= r.maxRequestPerBucket {
		r.rateBuckets[rateKey][r.numberBuckets-1]++
		r.metrics.rateLimiterRejects.WithLabelValues("bucket_" + r.Name()).Add(1)
		return false, r.bucketExceededErr
	}

	r.rateBuckets[rateKey][r.numberBuckets-1]++

	return true, nil
}

type FakeRateLimiter struct {
	BoolToReturn  bool
	ErrorToReturn error
}

func (f *FakeRateLimiter) AllowRequest(*models.Request) (bool, error) {
	return f.BoolToReturn, f.ErrorToReturn
}

func (f *FakeRateLimiter) Name() string {
	return "fake"
}
