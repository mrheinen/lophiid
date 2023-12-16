package backend

import (
	"loophid/pkg/database"
	"testing"
	"time"
)

func TestSessionCache(t *testing.T) {
	rule := database.ContentRule{
		ID: 42,
	}
	c := NewSessionCache(time.Second * 0)
	testIp := "127.0.0.1"

	// Store the test rule and a few extra
	c.Store(testIp, rule)
	c.Store("127.0.0.2", database.ContentRule{ID: 22})
	c.Store("127.0.0.3", database.ContentRule{ID: 23})
	c.Store("127.0.0.4", database.ContentRule{ID: 24})

	testRule, err := c.Get(testIp)
	if err != nil {
		t.Errorf("got error: %s", err)
	}

	if testRule.ID != rule.ID {
		t.Errorf("expected %d but got %d", rule.ID, testRule.ID)
	}

	rc := c.CleanExpired()
	if rc != 4 {
		t.Errorf("expected 4, got %d", rc)
	}

	// Cache is empty, try to remove something
	testRule, err = c.Get(testIp)
	if err == nil {
		t.Errorf("expected error but got rule %v", testRule)
	}
}

func TestSessionCacheDoesNotExpire(t *testing.T) {
	rule := database.ContentRule{
		ID: 42,
	}
	c := NewSessionCache(time.Hour * 3)
	testIp := "127.0.0.1"
	c.Store(testIp, rule)

	testRule, err := c.Get(testIp)
	if err != nil {
		t.Errorf("got error: %s", err)
	}

	if testRule.ID != rule.ID {
		t.Errorf("expected %d but got %d", rule.ID, testRule.ID)
	}

	rc := c.CleanExpired()
	if rc != 0 {
		t.Errorf("expected 0, got %d", rc)
	}
}
