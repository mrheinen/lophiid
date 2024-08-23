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
	return r.CleanExpiredWithCallback(func(T) bool { return true })
}

// CleanExpiredWithCallback is similar to CleanExpired but also calls the
// callback. If the callback returns true than the entry is removed.
// This can be used to do something with the cached data right before it expires
// in the cache.
func (r *StringMapCache[T]) CleanExpiredWithCallback(callback func(T) bool) (removedCount int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for k, v := range r.rules {
		if time.Since(v.Time) > r.timeout {
			if callback(v.Data) {
				slog.Debug("removing entry from cache", slog.String("name", r.cacheName), slog.String("key", k))
				removedCount++
				delete(r.rules, k)
			}
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
