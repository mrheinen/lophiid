package util

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type CacheEntry[T comparable] struct {
	Data T
	Time time.Time
}

type StringMapCache[T comparable] struct {
	mu        sync.Mutex
	rules     map[string]CacheEntry[T]
	timeout   time.Duration
	bgChan    chan bool
	cacheName string
}

func NewStringMapCache[T comparable](name string, timeout time.Duration) *StringMapCache[T] {
	return &StringMapCache[T]{
		timeout:   timeout,
		cacheName: name,
		rules:     make(map[string]CacheEntry[T]),
		bgChan:    make(chan bool),
	}
}

func (r *StringMapCache[T]) Store(key string, data T) {
	r.mu.Lock()
	r.rules[key] = CacheEntry[T]{
		Data: data,
		Time: time.Now(),
	}
	r.mu.Unlock()
}

func (r *StringMapCache[T]) Get(key string) (*T, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ce, ok := r.rules[key]

	if !ok {
		return nil, fmt.Errorf("cannot find: %s", key)
	}
	return &ce.Data, nil
}

// Returns the content of the cache as a map.
// Note that this returns a copy of the data. There is no guarantee that this
// copied data is still correct and in sync with the cache after calling
// this method. Only use this when that doesn't matter.
func (r *StringMapCache[T]) GetAsMap() map[string]T {
	r.mu.Lock()
	defer r.mu.Unlock()

	ret := make(map[string]T)
	for k, v := range r.rules {
		ret[k] = v.Data
	}

	return ret
}

func (r *StringMapCache[T]) CleanExpired() (removedCount int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for k, v := range r.rules {
		if time.Since(v.Time) > r.timeout {
			slog.Debug("removing entry from cache", slog.String("name", r.cacheName), slog.String("key", k))
			removedCount++
			delete(r.rules, k)
		}
	}

	slog.Debug("expiration stats after cleanup", slog.String("name", r.cacheName), slog.Int("count", len(r.rules)), slog.Int("removedCount", int(removedCount)))
	return
}

func (r *StringMapCache[T]) Start() {
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

func (r *StringMapCache[T]) Stop() {
	slog.Info("stopping cache", slog.String("name", r.cacheName))
	r.bgChan <- true
}
