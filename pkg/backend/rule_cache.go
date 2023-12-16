package backend

import (
	"fmt"
	"sync"
	"time"
)

type RuleVsContentCache struct {
	mu      sync.Mutex
	entries map[string]map[string]time.Time
	timeout time.Duration
}

func NewRuleVsContentCache(timeout time.Duration) *RuleVsContentCache {
	return &RuleVsContentCache{
		entries: make(map[string]map[string]time.Time),
		timeout: timeout,
	}
}

func (r *RuleVsContentCache) Store(sourceIp string, ruleId int64, contentId int64) {
	key := fmt.Sprintf("%d-%d", ruleId, contentId)

	r.mu.Lock()
	if _, ok := r.entries[sourceIp]; !ok {
		r.entries[sourceIp] = make(map[string]time.Time)
	}
	r.entries[sourceIp][key] = time.Now()
	r.mu.Unlock()
}

func (r *RuleVsContentCache) Has(sourceIp string, ruleId int64, contentId int64) bool {
	key := fmt.Sprintf("%d-%d", ruleId, contentId)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[sourceIp]; !ok {
		return false
	}
	_, ok := r.entries[sourceIp][key]
	return ok
}

func (r *RuleVsContentCache) CleanupExpired() {
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()
	for ip, keys := range r.entries {
		for key, t := range keys {
			if now.Sub(t) > r.timeout {
				delete(r.entries[ip], key)
			}
		}
		if len(r.entries[ip]) == 0 {
			delete(r.entries, ip)
		}
	}
}
