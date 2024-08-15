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
	"bytes"
	"log/slog"
	"lophiid/pkg/database"
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
	ipCache      util.StringMapCache[bool]
	lookupMap    map[string]int
	bgChan       chan bool
	maxAttempts  int
	mu           sync.Mutex
	whoisMetrics *WhoisMetrics
}

type RdapClientInterface interface {
	QueryIP(ip string) (*rdap.IPNetwork, error)
}

func NewCachedRdapManager(dbClient database.DatabaseClient, whoisMetrics *WhoisMetrics, rdapClient RdapClientInterface, cacheDuration time.Duration, maxAttempts int) *CachedRdapManager {
	return &CachedRdapManager{
		dbClient:     dbClient,
		whoisClient:  rdapClient,
		whoisMetrics: whoisMetrics,
		// The int value in the map indicates how many times we have tried to lookup
		// the whois for that given IP.
		lookupMap:   make(map[string]int),
		bgChan:      make(chan bool),
		maxAttempts: maxAttempts,
		ipCache:     *util.NewStringMapCache[bool]("whois_ip_cache", cacheDuration),
	}
}

func (c *CachedRdapManager) Start() {
	slog.Info("Starting Whois Rdap manager")
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
			c.ipCache.Store(ip, true)
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

		if _, err := c.dbClient.Insert(
			&database.Whois{
				IP:      ip,
				Data:    "",
				Rdap:    printerOutput.Bytes(),
				Country: resNetwork.Country,
			}); err != nil {
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

		// We don't actually cache the results, we just cache the fact that we have
		// seen this IP.
		c.ipCache.Store(ip, true)
		slog.Debug("Added whois record for IP", slog.String("ip", ip))
	}

	c.ipCache.CleanExpired()
}

func (c *CachedRdapManager) LookupIP(ip string) error {
	// If we have a cached entry for this IP then we can return
	// immediately and prevent doing a database query.
	_, err := c.ipCache.Get(ip)
	if err == nil {
		return nil
	}

	// Next check if there is an entry in the database already.
	_, err = c.dbClient.GetWhoisByIP(ip)
	if err == nil {
		// Update the cache to recored we already have an entry. In the future we
		// might want to look at the age of the entry.
		c.ipCache.Store(ip, true)
		return nil
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
