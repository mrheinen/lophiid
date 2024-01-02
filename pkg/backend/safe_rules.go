package backend

import (
	"sync"

	"loophid/pkg/database"
)

type SafeRules struct {
	mu    sync.Mutex
	rules []database.ContentRule
}

// GetRules returns a copy of the content rules.
func (s *SafeRules) Get() []database.ContentRule {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]database.ContentRule{}, s.rules...)
}

func (s *SafeRules) Set(rules []database.ContentRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = rules
}
