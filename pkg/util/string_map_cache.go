package util

import (
	"fmt"
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
}

func NewStringMapCache(timeout time.Duration) *StringMapCache {
	return &StringMapCache{
		timeout: timeout,
		rules:   make(map[string]CacheEntry),
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
