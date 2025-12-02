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

type CacheEntry[T any] struct {
	Data          T
	LastStoreTime time.Time
	CreationTime  time.Time
}

type StringMapCache[T any] struct {
	mu        sync.RWMutex
	entries   map[string]CacheEntry[T]
	timeout   time.Duration
	bgChan    chan bool
	cacheName string
}

func NewStringMapCache[T any](name string, timeout time.Duration) *StringMapCache[T] {
	return &StringMapCache[T]{
		timeout:   timeout,
		cacheName: name,
		entries:   make(map[string]CacheEntry[T]),
		bgChan:    make(chan bool),
	}
}

func (r *StringMapCache[T]) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

func (r *StringMapCache[T]) Lock() {
	r.mu.Lock()
}

func (r *StringMapCache[T]) Unlock() {
	r.mu.Unlock()
}

func (r *StringMapCache[T]) Store(key string, data T) {
	r.mu.Lock()
	r.entries[key] = CacheEntry[T]{
		Data:          data,
		LastStoreTime: time.Now(),
		CreationTime:  time.Now(),
	}
	r.mu.Unlock()
}

// Update the item and also update the cache timeout timestamp.
func (r *StringMapCache[T]) Update(key string, data T) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.entries[key]
	if !ok {
		return fmt.Errorf("no entry for key %s", key)
	}

	entry.Data = data
	entry.LastStoreTime = time.Now()
	r.entries[key] = entry

	return nil
}

// Replace replaces the data of an entry while preserving the timestamp meaning
// it has no influence on expiration.
func (r *StringMapCache[T]) Replace(key string, data T) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.entries[key]
	if !ok {
		return fmt.Errorf("no entry for key %s", key)
	}

	entry.Data = data
	r.entries[key] = entry

	return nil
}

// GetOrCreate atomically gets an existing entry or creates a new one using
// createFn, then runs the callback on the data while holding the lock.
// This avoids TOCTOU issues when checking and modifying cache entries.
func (r *StringMapCache[T]) GetOrCreate(key string, createFn func() T, callback func(*T)) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.entries[key]
	if !ok {
		entry = CacheEntry[T]{
			Data:          createFn(),
			LastStoreTime: time.Now(),
			CreationTime:  time.Now(),
		}
	}

	callback(&entry.Data)
	entry.LastStoreTime = time.Now()
	r.entries[key] = entry
}

// Check will lock the entry for `key` and will give run callback on the entry.
// This is useful if you want to check something in the map while having the
// lock.
func (r *StringMapCache[T]) Check(key string, callback func(T) bool) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.entries[key]
	if !ok {
		return false, fmt.Errorf("no entry for key %s", key)
	}

	return callback(entry.Data), nil
}

func (r *StringMapCache[T]) Get(key string) (*T, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ce, ok := r.entries[key]

	if !ok {
		return nil, fmt.Errorf("cannot find: %s", key)
	}
	return &ce.Data, nil
}

func (r *StringMapCache[T]) GetDurationStored(key string) (time.Duration, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ce, ok := r.entries[key]

	if !ok {
		return time.Second, fmt.Errorf("cannot find: %s", key)
	}
	return time.Since(ce.CreationTime), nil
}

// Returns the content of the cache as a map.
// Note that this returns a copy of the data. There is no guarantee that this
// copied data is still correct and in sync with the cache after calling
// this method. Only use this when that doesn't matter.
func (r *StringMapCache[T]) GetAsMap() map[string]T {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ret := make(map[string]T)
	for k, v := range r.entries {
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

	for k, v := range r.entries {
		if time.Since(v.LastStoreTime) > r.timeout {
			if callback(v.Data) {
				slog.Debug("removing entry from cache", slog.String("name", r.cacheName), slog.String("key", k))
				removedCount++
				delete(r.entries, k)
			}
		}
	}
	slog.Debug("expiration stats after cleanup", slog.String("name", r.cacheName), slog.Int("count", len(r.entries)), slog.Int("removedCount", int(removedCount)))
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

func (r *StringMapCache[T]) StartWithCallback(callback func(T) bool) {
	ticker := time.NewTicker(time.Minute * 1)
	go func() {
		for {
			select {
			case <-r.bgChan:
				ticker.Stop()
				return
			case <-ticker.C:
				r.CleanExpiredWithCallback(callback)
			}
		}
	}()
}

func (r *StringMapCache[T]) Stop() {
	slog.Info("stopping cache", slog.String("name", r.cacheName))
	r.bgChan <- true
}
