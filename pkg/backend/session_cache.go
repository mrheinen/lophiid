package backend

import (
	"fmt"
	"loophid/pkg/database"
	"sync"
	"time"
)

type CacheEntry struct {
	Rule database.ContentRule
	Time time.Time
}

type SessionCache struct {
	mu      sync.Mutex
	rules   map[string]CacheEntry
	timeout time.Duration
}

func NewSessionCache(timeout time.Duration) *SessionCache {
	return &SessionCache{
		timeout: timeout,
		rules:   make(map[string]CacheEntry),
	}
}

func (r *SessionCache) Store(sourceIp string, rule database.ContentRule) {
	r.mu.Lock()
	r.rules[sourceIp] = CacheEntry{
		Rule: rule,
		Time: time.Now(),
	}
	r.mu.Unlock()
}

func (r *SessionCache) Get(sourceIp string) (database.ContentRule, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ce, ok := r.rules[sourceIp]

	if !ok {
		return database.ContentRule{}, fmt.Errorf("cannot find: %s", sourceIp)
	}
	return ce.Rule, nil
}

func (r *SessionCache) CleanExpired() (removedCount int64) {
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
