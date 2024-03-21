package whois

import (
	"errors"
	"loophid/pkg/database"
	"testing"
	"time"
)

type FakeWhoisClient struct {
	ErrorToReturn error
}

func (f *FakeWhoisClient) Whois(domain string, servers ...string) (result string, err error) {
	return "", f.ErrorToReturn
}

func TestDoWhoisWorkCachesDatabaseMatch(t *testing.T) {
	dbc := database.FakeDatabaseClient{
		WhoisToReturn:      database.Whois{},
		WhoisErrorToReturn: nil,
	}
	testIP := "1.1.1.1"
	wc := FakeWhoisClient{}
	mgr := NewCachedWhoisManager(&dbc, &wc, time.Second, 3)

	// Check that the IP is not in the cache.
	if _, err := mgr.ipCache.Get(testIP); err == nil {
		t.Errorf("unexpected entry in cache")
	}

	// Do the lookup. Because the database returns nil, the lookup returns quickly
	// and successfully.
	if err := mgr.LookupIP(testIP); err != nil {
		t.Errorf("got unexpected error: %s", err)
	}

	// Check that the cache was updated.
	if _, err := mgr.ipCache.Get(testIP); err != nil {
		t.Errorf("expected entry to be in cache")
	}
}

func TestDoWhoisWorkRetries(t *testing.T) {
	dbc := database.FakeDatabaseClient{
		WhoisToReturn:      database.Whois{},
		WhoisErrorToReturn: errors.New("missing"),
	}
	testIP := "1.1.1.1"
	wc := FakeWhoisClient{
		ErrorToReturn: errors.New("fail"),
	}

	mgr := NewCachedWhoisManager(&dbc, &wc, time.Second, 3)

	// Do the lookup, The database will return an error which simulates the
	// scenario where there is no record already in the database. As a result the
	// IP should be added to the lookupMap for scheduling.
	if err := mgr.LookupIP(testIP); err != nil {
		t.Errorf("got unexpected error: %s", err)
	}

	// Nothing should be cached at the moment
	if _, err := mgr.ipCache.Get(testIP); err == nil {
		t.Errorf("unexpected entry in cache")
	}

	v, ok := mgr.lookupMap[testIP]
	if !ok {
		t.Errorf("IP did not get scheduled in lookupMap")
	}

	if v != 0 {
		t.Errorf("expected %d, got %d", 0, v)
	}

	// Now lets do the actual lookup. However, because we configured the fake
	// whois client to return an error, we expect the operation to fail and the
	// value of the lookupMap to increase.

	for i := 1; i <= mgr.maxAttempts; i += 1 {
		mgr.DoWhoisWork()
		if mgr.lookupMap[testIP] != i {
			t.Errorf("Expected %d, got %d", i, mgr.lookupMap[testIP])
		}
	}

	// We did the maxAttempts so if we call DoWhoisWork again then the entry will
	// be removed from the lookupMap
	mgr.DoWhoisWork()
	_, ok = mgr.lookupMap[testIP]
	if ok {
		t.Errorf("Expected lookupMap entry to be removed. Instead it has value %d", mgr.lookupMap[testIP])
	}
}
