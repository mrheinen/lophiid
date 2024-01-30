package util

import (
	"testing"
	"time"
)

func TestStringMapCache(t *testing.T) {
	c := NewStringMapCache(time.Second * 0)
	testIp := "127.0.0.1"

	// Store the test rule and a few extra
	c.Store(testIp, "22")
	c.Store("127.0.0.3", "23")
	c.Store("127.0.0.4", "24")

	ret, err := c.Get(testIp)
	if err != nil {
		t.Errorf("got error: %s", err)
	}

	testRet := ret.(string)
	if testRet != "22" {
		t.Errorf("expected 22 but got %s",  testRet)
	}

	rc := c.CleanExpired()
	if rc != 3 {
		t.Errorf("expected 4, got %d", rc)
	}

	// Cache is empty, try to remove something
	ret, err = c.Get(testIp)
	if err == nil {
		t.Errorf("expected error but got rule %v", ret)
	}
}

func TestStringMapCacheDoesNotExpire(t *testing.T) {
	c := NewStringMapCache(time.Hour * 3)
	testIp := "127.0.0.1"
	c.Store(testIp, "22")

	ret, err := c.Get(testIp)
	if err != nil {
		t.Errorf("got error: %s", err)
	}

	testRet := ret.(string)
	if testRet != "22" {
		t.Errorf("expected 22 but got %s", testRet)
	}

	rc := c.CleanExpired()
	if rc != 0 {
		t.Errorf("expected 0, got %d", rc)
	}
}
