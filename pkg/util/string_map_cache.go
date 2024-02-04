package util

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type CacheEntry struct {
	Data any
	Time time.Time
}

type StringMapCache struct {
	mu      sync.Mutex
	rules   map[string]CacheEntry
	timeout time.Duration
	bgChan  chan bool
}

func NewStringMapCache(timeout time.Duration) *StringMapCache {
	return &StringMapCache{
		timeout: timeout,
		rules:   make(map[string]CacheEntry),
		bgChan:  make(chan bool),
	}
}

func (r *StringMapCache) Store(key string, data any) {
	r.mu.Lock()
	r.rules[key] = CacheEntry{
		Data: data,
		Time: time.Now(),
	}
	r.mu.Unlock()
}

func (r *StringMapCache) Get(key string) (interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ce, ok := r.rules[key]

	if !ok {
		return nil, fmt.Errorf("cannot find: %s", key)
	}
	return ce.Data, nil
}

func (r *StringMapCache) CleanExpired() (removedCount int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	removedCount = 0
	for k, v := range r.rules {
		d := now.Sub(v.Time)
		if d > r.timeout {
			fmt.Printf("Removing entry for: %s\n", k)
			removedCount++
			delete(r.rules, k)
		}
	}
	return removedCount
}

func (r *StringMapCache) Start() {
	ticker := time.NewTicker(time.Minute * 1)
	go func() {
		for {
			select {
			case <-r.bgChan:
				ticker.Stop()
				return
			case <-ticker.C:
				r.CleanExpired()
			}
		}
	}()
}

func (r *StringMapCache) Stop() {
	slog.Info("stopping cache")
	r.bgChan <- true
}
