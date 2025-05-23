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
	"testing"
	"time"
)

func TestStringMapCache(t *testing.T) {
	c := NewStringMapCache[string]("test", time.Second*0)
	testKey := "127.0.0.1"

	// Store the test rule and a few extra
	c.Store(testKey, "22")
	c.Store("127.0.0.3", "23")
	c.Store("127.0.0.4", "24")

	ret, err := c.Get(testKey)
	if err != nil {
		t.Errorf("got error: %s", err)
	}

	if *ret != "22" {
		t.Errorf("expected 22 but got %s", *ret)
	}

	expectedCurrentEntries := 3
	if c.Count() != expectedCurrentEntries {
		t.Errorf("expected %d, got %d", expectedCurrentEntries, c.Count())
	}

	rc := c.CleanExpired()
	if rc != int64(expectedCurrentEntries) {
		t.Errorf("expected %d, got %d", expectedCurrentEntries, rc)
	}

	// Cache is empty, try to remove something
	ret, err = c.Get(testKey)
	if err == nil {
		t.Errorf("expected error but got rule %v", *ret)
	}
}

func TestStringMapCacheCleanupWithCallback(t *testing.T) {
	c := NewStringMapCache[string]("test", time.Second*0)
	testKey := "127.0.0.1"

	// Store the test rule and a few extra
	c.Store(testKey, "22")
	c.Store("127.0.0.3", "23")
	c.Store("127.0.0.4", "24")

	rc := c.CleanExpiredWithCallback(func(string) bool { return false })
	if rc != 0 {
		t.Errorf("expected 0, got %d", rc)
	}

	rc = c.CleanExpiredWithCallback(func(string) bool { return true })
	if rc != 3 {
		t.Errorf("expected 3, got %d", rc)
	}
}

func TestStringMapCacheCacheMiss(t *testing.T) {
	c := NewStringMapCache[string]("test", time.Second*0)

	_, err := c.Get("1.2.3.4")
	if err == nil {
		t.Errorf("expected error, got none.")
	}
}

func TestStringMapCacheDoesNotExpire(t *testing.T) {
	c := NewStringMapCache[string]("test", time.Hour*3)
	testIp := "127.0.0.1"
	c.Store(testIp, "22")

	ret, err := c.Get(testIp)
	if err != nil {
		t.Errorf("got error: %s", err)
	}

	if *ret != "22" {
		t.Errorf("expected 22 but got %s", *ret)
	}

	rc := c.CleanExpired()
	if rc != 0 {
		t.Errorf("expected 0, got %d", rc)
	}
}

func TestStringMapCacheCheck(t *testing.T) {
	c := NewStringMapCache[string]("test", time.Second*0)
	testKey := "127.0.0.1"

	// Store a test value
	c.Store(testKey, "22")

	// Test successful check with callback returning true
	result, err := c.Check(testKey, func(data string) bool {
		return data == "22"
	})
	if err != nil {
		t.Errorf("got error: %s", err)
	}
	if !result {
		t.Errorf("expected callback to return true, got false")
	}

	// Test successful check with callback returning false
	result, err = c.Check(testKey, func(data string) bool {
		return data == "wrong-value"
	})
	if err != nil {
		t.Errorf("got error: %s", err)
	}
	if result {
		t.Errorf("expected callback to return false, got true")
	}

	// Test check with non-existent key
	nonExistentKey := "non-existent-key"
	result, err = c.Check(nonExistentKey, func(data string) bool {
		return true
	})
	if err == nil {
		t.Errorf("expected error for non-existent key, got none")
	}
	if result {
		t.Errorf("expected result to be false for non-existent key, got true")
	}

	// Test check with more complex logic in callback
	c.Store("key1", "value1")
	c.Store("key2", "value2")
	
	var capturedValue string
	result, err = c.Check("key1", func(data string) bool {
		capturedValue = data
		return len(data) >= 6
	})
	if err != nil {
		t.Errorf("got error: %s", err)
	}
	if !result {
		t.Errorf("expected callback to return true (len >= 6), got false")
	}
	if capturedValue != "value1" {
		t.Errorf("expected captured value to be 'value1', got '%s'", capturedValue)
	}
}
