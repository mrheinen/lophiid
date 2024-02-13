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
	mu      sync.Mutex
	rules   map[string]CacheEntry[T]
	timeout time.Duration
	bgChan  chan bool
}

func NewStringMapCache[T comparable](timeout time.Duration) *StringMapCache[T] {
	return &StringMapCache[T]{
		timeout: timeout,
		rules:   make(map[string]CacheEntry[T]),
		bgChan:  make(chan bool),
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

func (r *StringMapCache[T]) CleanExpired() (removedCount int64) {
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
	slog.Info("stopping cache")
	r.bgChan <- true
}
