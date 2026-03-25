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
package whois

import (
	"errors"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"testing"
	"time"

	"github.com/openrdap/rdap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

type FakeRdapClient struct {
	ErrorToReturn error
}

func (f *FakeRdapClient) QueryIP(ip string) (*rdap.IPNetwork, error) {

	ret := rdap.IPNetwork{
		Country: "NL",
	}
	return &ret, f.ErrorToReturn
}

func TestDoWhoisRdapWorkCachesDatabaseMatch(t *testing.T) {
	dbc := database.FakeDatabaseClient{
		WhoisModelsToReturn: []models.Whois{models.Whois{}},
		WhoisErrorToReturn:  nil,
	}
	testIP := "1.1.1.1"
	wc := FakeRdapClient{}
	reg := prometheus.NewRegistry()
	metrics := CreateWhoisMetrics(reg)

	mgr := NewCachedRdapManager(&dbc, metrics, &wc, time.Second, 3, nil)

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

func TestDoWhoisRdapWorksOk(t *testing.T) {
	dbc := database.FakeDatabaseClient{
		WhoisModelsToReturn: []models.Whois{models.Whois{}},
		WhoisErrorToReturn:  errors.New("fail"),
	}
	testIP := "1.1.1.1"
	wc := FakeRdapClient{
		ErrorToReturn: nil,
	}

	reg := prometheus.NewRegistry()
	metrics := CreateWhoisMetrics(reg)

	mgr := NewCachedRdapManager(&dbc, metrics, &wc, time.Second, 3, nil)

	_, ok := mgr.lookupMap[testIP]
	if ok {
		t.Errorf("Unexpectedly found IP in lookup map")
	}

	// Do the lookup. Because the database returns nil, the lookup returns quickly
	// and successfully.
	if err := mgr.LookupIP(testIP); err != nil {
		t.Errorf("got unexpected error: %s", err)
	}

	_, ok = mgr.lookupMap[testIP]
	if !ok {
		t.Errorf("expected IP in lookup map")
	}

	mgr.DoWhoisWork()

	_, ok = mgr.lookupMap[testIP]
	if ok {
		t.Errorf("Unexpectedly found IP in lookup map")
	}

}

func TestDoWhoisRdapWorkRetries(t *testing.T) {
	dbc := database.FakeDatabaseClient{
		WhoisModelsToReturn: []models.Whois{models.Whois{}},
		WhoisErrorToReturn:  errors.New("missing"),
	}
	testIP := "1.1.1.1"
	wc := FakeRdapClient{
		ErrorToReturn: errors.New("fail"),
	}

	reg := prometheus.NewRegistry()
	metrics := CreateWhoisMetrics(reg)

	mgr := NewCachedRdapManager(&dbc, metrics, &wc, time.Second, 3, nil)

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
			metric := testutil.ToFloat64(metrics.whoisRetriesCount)
			if int(metric) != i {
				t.Errorf("expected 1, got %f", metric)
			}

			t.Errorf("Expected %d, got %d", i, mgr.lookupMap[testIP])
		}
	}

	metric := testutil.ToFloat64(metrics.whoisRetriesExceededCount)
	if int(metric) != 0 {
		t.Errorf("expected 0, got %f", metric)
	}

	// We did the maxAttempts so if we call DoWhoisWork again then the entry will
	// be removed from the lookupMap
	mgr.DoWhoisWork()

	metric = testutil.ToFloat64(metrics.whoisRetriesExceededCount)
	if int(metric) != 1 {
		t.Errorf("expected 1, got %f", metric)
	}

	_, ok = mgr.lookupMap[testIP]
	if ok {
		t.Errorf("Expected lookupMap entry to be removed. Instead it has value %d", mgr.lookupMap[testIP])
	}
}

func TestDoWhoisWorkEnrichesWithGeoIP(t *testing.T) {
	dbc := database.FakeDatabaseClient{
		WhoisModelsToReturn: []models.Whois{},
		WhoisErrorToReturn:  errors.New("missing"),
	}
	testIP := "1.1.1.1"
	wc := FakeRdapClient{
		ErrorToReturn: nil,
	}

	expectedGeoIP := &GeoIPResult{
		Country:        "Netherlands",
		CountryCode:    "NL",
		Continent:      "EU",
		City:           "Amsterdam",
		Latitude:       52.3676,
		Longitude:      4.9041,
		Timezone:       "Europe/Amsterdam",
		AccuracyRadius: 100,
		IsInEU:         true,
		ASN:            1234,
		ASNOrg:         "Test Org",
	}

	fakeGeoIP := &FakeGeoIPLookup{
		ResultToReturn: expectedGeoIP,
		ErrorToReturn:  nil,
	}

	reg := prometheus.NewRegistry()
	metrics := CreateWhoisMetrics(reg)

	mgr := NewCachedRdapManager(&dbc, metrics, &wc, time.Second, 3, fakeGeoIP)

	if err := mgr.LookupIP(testIP); err != nil {
		t.Errorf("got unexpected error: %s", err)
	}

	mgr.DoWhoisWork()

	// Verify the inserted model has GeoIP fields populated.
	inserted, ok := dbc.LastDataModelSeen.(*models.Whois)
	if !ok {
		t.Fatal("expected Insert to be called with *models.Whois")
	}

	assert.Equal(t, "Netherlands", inserted.GeoIPCountry)
	assert.Equal(t, "NL", inserted.GeoIPCountryCode)
	assert.Equal(t, "EU", inserted.GeoIPContinent)
	assert.Equal(t, "Amsterdam", inserted.GeoIPCity)
	assert.Equal(t, 52.3676, inserted.GeoIPLatitude)
	assert.Equal(t, 4.9041, inserted.GeoIPLongitude)
	assert.Equal(t, "Europe/Amsterdam", inserted.GeoIPTimezone)
	assert.Equal(t, uint16(100), inserted.GeoIPAccuracyRadius)
	assert.True(t, inserted.GeoIPIsInEU)
	assert.Equal(t, uint(1234), inserted.GeoIPASN)
	assert.Equal(t, "Test Org", inserted.GeoIPASNOrg)
}

func TestDoWhoisWorkGeoIPErrorIsNonFatal(t *testing.T) {
	dbc := database.FakeDatabaseClient{
		WhoisModelsToReturn: []models.Whois{},
		WhoisErrorToReturn:  errors.New("missing"),
	}
	testIP := "1.1.1.1"
	wc := FakeRdapClient{
		ErrorToReturn: nil,
	}

	fakeGeoIP := &FakeGeoIPLookup{
		ResultToReturn: nil,
		ErrorToReturn:  errors.New("geoip failed"),
	}

	reg := prometheus.NewRegistry()
	metrics := CreateWhoisMetrics(reg)

	mgr := NewCachedRdapManager(&dbc, metrics, &wc, time.Second, 3, fakeGeoIP)

	if err := mgr.LookupIP(testIP); err != nil {
		t.Errorf("got unexpected error: %s", err)
	}

	// DoWhoisWork should still succeed and insert the record despite GeoIP failure.
	mgr.DoWhoisWork()

	// The record should have been inserted (IP removed from lookupMap).
	_, ok := mgr.lookupMap[testIP]
	if ok {
		t.Errorf("expected IP to be removed from lookupMap after successful insert")
	}

	// GeoIP fields should be zero-valued.
	inserted, ok := dbc.LastDataModelSeen.(*models.Whois)
	if !ok {
		t.Fatal("expected Insert to be called with *models.Whois")
	}
	assert.Equal(t, "", inserted.GeoIPCountry)
	assert.Equal(t, uint(0), inserted.GeoIPASN)

	// Verify the error metric was incremented.
	metric := testutil.ToFloat64(metrics.geoipLookupErrorCount)
	assert.Equal(t, float64(1), metric)
}

func TestDoWhoisWorkGeoIPCacheHit(t *testing.T) {
	dbc := database.FakeDatabaseClient{
		WhoisModelsToReturn: []models.Whois{},
		WhoisErrorToReturn:  errors.New("missing"),
	}
	testIP := "1.1.1.1"
	wc := FakeRdapClient{
		ErrorToReturn: nil,
	}

	fakeGeoIP := &FakeGeoIPLookup{
		ResultToReturn: &GeoIPResult{
			Country:     "Germany",
			CountryCode: "DE",
		},
		ErrorToReturn: nil,
	}

	reg := prometheus.NewRegistry()
	metrics := CreateWhoisMetrics(reg)

	mgr := NewCachedRdapManager(&dbc, metrics, &wc, time.Second, 3, fakeGeoIP)

	// Pre-populate the ipCache with a whois record that has GeoIP data.
	// This simulates a previously enriched record already being cached.
	mgr.ipCache.Store(testIP, models.Whois{
		IP:               testIP,
		GeoIPCountry:     "Cached Country",
		GeoIPCountryCode: "CC",
	})

	// LookupIP should find the IP in the cache and not schedule a lookup.
	if err := mgr.LookupIP(testIP); err != nil {
		t.Errorf("got unexpected error: %s", err)
	}

	// The IP should NOT be in the lookupMap because the cache hit prevents scheduling.
	_, ok := mgr.lookupMap[testIP]
	assert.False(t, ok, "expected IP to NOT be in lookupMap due to cache hit")

	// Verify the cached record has the expected GeoIP data.
	cached, err := mgr.ipCache.Get(testIP)
	assert.NoError(t, err)
	assert.Equal(t, "Cached Country", cached.GeoIPCountry)
	assert.Equal(t, "CC", cached.GeoIPCountryCode)
}
