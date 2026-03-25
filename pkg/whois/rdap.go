// Lophiid distributed honeypot
// Copyright (C) 2023-2026 Niels Heinen
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
	"bytes"
	"fmt"
	"log/slog"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util"
	"sync"
	"time"

	"github.com/openrdap/rdap"
)

type RdapManager interface {
	LookupIP(ip string) error
}

type CachedRdapManager struct {
	dbClient     database.DatabaseClient
	whoisClient  RdapClientInterface
	ipCache      util.StringMapCache[models.Whois]
	geoIPLookup  GeoIPLookup
	lookupMap    map[string]int
	bgChan       chan bool
	maxAttempts  int
	mu           sync.Mutex
	whoisMetrics *WhoisMetrics
}

type RdapClientInterface interface {
	QueryIP(ip string) (*rdap.IPNetwork, error)
}

// NewCachedRdapManager creates a new CachedRdapManager. The geoIPLookup
// parameter may be nil to disable GeoIP enrichment.
func NewCachedRdapManager(dbClient database.DatabaseClient, whoisMetrics *WhoisMetrics, rdapClient RdapClientInterface, cacheDuration time.Duration, maxAttempts int, geoIPLookup GeoIPLookup) *CachedRdapManager {
	return &CachedRdapManager{
		dbClient:     dbClient,
		whoisClient:  rdapClient,
		whoisMetrics: whoisMetrics,
		geoIPLookup:  geoIPLookup,
		// The int value in the map indicates how many times we have tried to lookup
		// the whois for that given IP.
		lookupMap:   make(map[string]int),
		bgChan:      make(chan bool),
		maxAttempts: maxAttempts,
		ipCache:     *util.NewStringMapCache[models.Whois]("whois_ip_cache", cacheDuration),
	}
}

func (c *CachedRdapManager) Start() {
	slog.Info("Starting Whois Rdap manager")
	c.ipCache.Start()

	ticker := time.NewTicker(time.Second * 10)
	go func() {
		for {
			select {
			case <-c.bgChan:
				ticker.Stop()
				return
			case <-ticker.C:
				c.DoWhoisWork()
			}
		}
	}()
}

func (c *CachedRdapManager) Stop() {
	slog.Info("Stopping Whois Rdap manager")
	c.geoIPLookup.Close()
	c.ipCache.Stop()
	c.bgChan <- true
}

// DoWhoisWork will perform the whois query for the IPs in the lookupMap.
func (c *CachedRdapManager) DoWhoisWork() {
	var ips []string

	c.mu.Lock()
	for ip, lookupCount := range c.lookupMap {
		if lookupCount >= c.maxAttempts {
			slog.Warn("Removing IP from whois lookups. Exceeds # tries.", slog.String("ip", ip))
			c.whoisMetrics.whoisRetriesExceededCount.Inc()
			delete(c.lookupMap, ip)

			// Pretend we actually have the results. This will prevent new lookups
			// from happening.
			c.ipCache.Store(ip, models.Whois{IP: ip})
			continue
		}
		ips = append(ips, ip)
	}
	c.mu.Unlock()

	for _, ip := range ips {
		startTime := time.Now()
		resNetwork, err := c.whoisClient.QueryIP(ip)
		c.whoisMetrics.whoisLookupResponseTime.Observe(time.Since(startTime).Seconds())

		if err != nil {
			slog.Warn("Failed to lookup whois for IP", slog.String("ip", ip), slog.String("error", err.Error()))
			c.whoisMetrics.whoisRetriesCount.Inc()
			c.mu.Lock()
			c.lookupMap[ip] += 1
			c.mu.Unlock()
			continue
		}

		rdapPrinter := rdap.Printer{}
		var printerOutput bytes.Buffer
		rdapPrinter.Writer = &printerOutput

		// Todo: condider these options below
		// rdapPrinter.OmitNotices = true
		// rdapPrinter.OmitRemarks = true

		rdapPrinter.Print(resNetwork)

		whoisRecord := models.Whois{
			IP:      ip,
			Data:    "",
			Rdap:    printerOutput.Bytes(),
			Country: resNetwork.Country,
		}

		// Enrich with GeoIP data if enabled.
		if c.geoIPLookup != nil {
			c.enrichWithGeoIP(ip, &whoisRecord)
		}

		if _, err := c.dbClient.Insert(&whoisRecord); err != nil {
			slog.Warn("Failed to store whois in database", slog.String("error", err.Error()))
			c.whoisMetrics.whoisRetriesCount.Inc()
			c.mu.Lock()
			c.lookupMap[ip] += 1
			c.mu.Unlock()
			continue
		}

		c.mu.Lock()
		delete(c.lookupMap, ip)
		c.mu.Unlock()

		c.ipCache.Store(ip, whoisRecord)
		slog.Debug("Added whois record for IP", slog.String("ip", ip))
	}
}

// enrichWithGeoIP performs a GeoIP lookup for the given IP and populates the
// GeoIP fields on the Whois record. Errors are logged but do not prevent the
// whois record from being stored.
func (c *CachedRdapManager) enrichWithGeoIP(ip string, record *models.Whois) {
	startTime := time.Now()
	result, err := c.geoIPLookup.Lookup(ip)
	c.whoisMetrics.geoipLookupResponseTime.Observe(time.Since(startTime).Seconds())

	if err != nil {
		slog.Warn("GeoIP lookup failed", slog.String("ip", ip), slog.String("error", err.Error()))
		c.whoisMetrics.geoipLookupErrorCount.Inc()
		return
	}

	ApplyGeoIPResult(record, result)
}

// ApplyGeoIPResult copies GeoIPResult fields into the Whois model.
func ApplyGeoIPResult(record *models.Whois, result *GeoIPResult) {
	record.GeoIPCountry = result.Country
	record.GeoIPCountryCode = result.CountryCode
	record.GeoIPContinent = result.Continent
	record.GeoIPCity = result.City
	record.GeoIPLatitude = result.Latitude
	record.GeoIPLongitude = result.Longitude
	record.GeoIPTimezone = result.Timezone
	record.GeoIPAccuracyRadius = result.AccuracyRadius
	record.GeoIPIsInEU = result.IsInEU
	record.GeoIPASN = result.ASN
	record.GeoIPASNOrg = result.ASNOrg
}

func (c *CachedRdapManager) LookupIP(ip string) error {
	// If we have a cached entry for this IP then we can return
	// immediately and prevent doing a database query.
	_, err := c.ipCache.Get(ip)
	if err == nil {
		return nil
	}

	// Next check if there is an entry in the database already.
	hps, err := c.dbClient.SearchWhois(0, 1, fmt.Sprintf("ip:%s", ip))
	if err != nil {
		slog.Error("Failed to query whois in database", slog.String("error", err.Error()))

	} else {
		if len(hps) != 0 {
			// Update the cache with the existing record. In the future we
			// might want to look at the age of the entry.
			c.ipCache.Store(ip, hps[0])
			return nil
		}
	}

	// Schedule for lookup, if not already in the map
	c.mu.Lock()
	if _, ok := c.lookupMap[ip]; !ok {
		c.lookupMap[ip] = 0
	}
	c.mu.Unlock()
	return nil
}

type FakeRdapManager struct {
}

func (f *FakeRdapManager) LookupIP(ip string) error {
	return nil
}
