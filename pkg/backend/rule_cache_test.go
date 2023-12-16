package backend

import (
	"testing"
	"time"
)

func TestNewRuleVsContentCache(t *testing.T) {
	c := NewRuleVsContentCache(0)

	sIP := "1.1.1.1"
	rID := int64(1)
	cID := int64(10)

	c.Store(sIP, rID, cID)

	// Check if it is there.
	if !c.Has(sIP, rID, cID) {
		t.Error("cache misses our entry")
	}

	c.CleanupExpired()
	if c.Has(sIP, rID, cID) {
		t.Error("cache has our entry")
	}
}

func TestNewRuleVsContentCacheLongTimeout(t *testing.T) {
	c := NewRuleVsContentCache(time.Hour * 5)

	sIP := "1.1.1.1"
	rID := int64(1)
	cID := int64(10)

	c.Store(sIP, rID, cID)

	// Check if it is there.
	if !c.Has(sIP, rID, cID) {
		t.Error("cache misses our entry")
	}

	// Because of the long timeout this should be a noop
	c.CleanupExpired()

	if !c.Has(sIP, rID, cID) {
		t.Error("cache should have had our entry")
	}
}
