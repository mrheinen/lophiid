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
}

// WindowRateLimiter can be used to limit requests per HoneypotIP, Server port
// and SourceIP combination.  If BucketDuration is set to 1 minute and
// RateWindow is set to one hour then:
//
//	The ratelimiter will only allow MaxRequestPerBucket requests per minute
//	The ratelimiter will only allow MaxRequestsPerWindow per the entire hour
//
// When any of these limits are met than the AllowRequest() method will return
// false.
//
// Requires Start() to be called before usage.
type WindowRateLimiter struct {
	MaxIPRequestsPerWindow  int
	MaxIPRequestPerBucket   int
	MaxURIRequestsPerWindow int
	MaxURIRequestPerBucket  int
	RateWindow              time.Duration
	BucketDuration          time.Duration
	NumberBuckets           int
	IPRateBuckets           map[string][]int
	URIRateBuckets          map[string][]int
	Metrics                 *RatelimiterMetrics
	rateIPMu                sync.Mutex
	rateURIMu               sync.Mutex
	bgChan                  chan bool
}

func NewWindowRateLimiter(rateWindow time.Duration, bucketDuration time.Duration, maxIpRequestsPerWindow int, maxIpRequestPerBucket int, maxUriRequestsPerWindow int, maxUriRequestPerBucket int, metrics *RatelimiterMetrics) *WindowRateLimiter {
	slog.Info("Creating ratelimiter", slog.String("window_size", rateWindow.String()), slog.String("bucket_size", bucketDuration.String()))
	return &WindowRateLimiter{
		BucketDuration:          bucketDuration,
		MaxIPRequestPerBucket:   maxIpRequestPerBucket,
		MaxIPRequestsPerWindow:  maxIpRequestsPerWindow,
		MaxURIRequestPerBucket:  maxUriRequestPerBucket,
		MaxURIRequestsPerWindow: maxUriRequestsPerWindow,
		RateWindow:              rateWindow,
		IPRateBuckets:           make(map[string][]int),
		URIRateBuckets:          make(map[string][]int),
		NumberBuckets:           int(rateWindow / bucketDuration),
		Metrics:                 metrics,
		bgChan:                  make(chan bool),
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
	r.rateIPMu.Lock()
	for k := range r.IPRateBuckets {
		r.IPRateBuckets[k] = r.IPRateBuckets[k][1:]
		r.IPRateBuckets[k] = append(r.IPRateBuckets[k], 0)

		if GetSumOfWindow(r.IPRateBuckets[k]) == 0 {
			delete(r.IPRateBuckets, k)
		}
	}
	r.rateIPMu.Unlock()

	r.rateURIMu.Lock()
	for k := range r.URIRateBuckets {
		r.URIRateBuckets[k] = r.URIRateBuckets[k][1:]
		r.URIRateBuckets[k] = append(r.URIRateBuckets[k], 0)

		if GetSumOfWindow(r.URIRateBuckets[k]) == 0 {
			delete(r.URIRateBuckets, k)
		}
	}
	r.rateURIMu.Unlock()

	r.Metrics.ipRateBucketsGauge.Set(float64(len(r.IPRateBuckets)))
	r.Metrics.uriRateBucketsGauge.Set(float64(len(r.URIRateBuckets)))
}

// AllowRequest will return true if a request is allowed because the total
// requests in a window or bucket is not exceeded. If a request is not allowed
// then an error is returned with the reason why.
// Requires that Start() has been called before usage.
func (r *WindowRateLimiter) AllowRequest(req *models.Request) (bool, error) {
	ret, err := r.allowRequestForIP(req)
	if !ret {
		return ret, err
	}

	return r.allowRequestForURI(req)
}

func (r *WindowRateLimiter) allowRequestForIP(req *models.Request) (bool, error) {

	ipRateKey := fmt.Sprintf("%s-%d-%s", req.HoneypotIP, req.Port, req.SourceIP)
	r.rateIPMu.Lock()
	defer r.rateIPMu.Unlock()

	_, ok := r.IPRateBuckets[ipRateKey]
	// If the key is not present then this IP has no recent requests logged so we
	// create the buckets.
	if !ok {
		r.IPRateBuckets[ipRateKey] = make([]int, r.NumberBuckets)
		r.IPRateBuckets[ipRateKey][r.NumberBuckets-1] = 1
		return true, nil
	}

	// Check how many requests there have been in this window.
	if GetSumOfWindow(r.IPRateBuckets[ipRateKey]) >= r.MaxIPRequestsPerWindow {
		r.IPRateBuckets[ipRateKey][r.NumberBuckets-1] += 1
		return false, ErrIPWindowLimitExceeded
	}

	// Check if the bucket limit is not already exceeded.
	if r.IPRateBuckets[ipRateKey][r.NumberBuckets-1] >= r.MaxIPRequestPerBucket {
		r.IPRateBuckets[ipRateKey][r.NumberBuckets-1] += 1
		return false, ErrIPBucketLimitExceeded
	}

	r.IPRateBuckets[ipRateKey][r.NumberBuckets-1] += 1

	return true, nil
}

func (r *WindowRateLimiter) allowRequestForURI(req *models.Request) (bool, error) {
	uriRateKey := req.BaseHash

	r.rateURIMu.Lock()
	defer r.rateURIMu.Unlock()

	_, ok := r.URIRateBuckets[uriRateKey]
	// If the key is not present then this URI has no recent requests logged so we
	// create the buckets.
	if !ok {
		r.URIRateBuckets[uriRateKey] = make([]int, r.NumberBuckets)
		r.URIRateBuckets[uriRateKey][r.NumberBuckets-1] = 1
		return true, nil
	}

	// Check how many requests there have been in this window.
	if GetSumOfWindow(r.URIRateBuckets[uriRateKey]) >= r.MaxURIRequestsPerWindow {
		r.URIRateBuckets[uriRateKey][r.NumberBuckets-1] += 1
		return false, ErrURIWindowLimitExceeded
	}

	// Check if the bucket limit is not already exceeded.
	if r.URIRateBuckets[uriRateKey][r.NumberBuckets-1] >= r.MaxURIRequestPerBucket {
		r.URIRateBuckets[uriRateKey][r.NumberBuckets-1] += 1
		return false, ErrURIBucketLimitExceeded
	}

	r.URIRateBuckets[uriRateKey][r.NumberBuckets-1] += 1

	return true, nil
}

type FakeRateLimiter struct {
	BoolToReturn  bool
	ErrorToReturn error
}

func (f *FakeRateLimiter) AllowRequest(*models.Request) (bool, error) {
	return f.BoolToReturn, f.ErrorToReturn
}
