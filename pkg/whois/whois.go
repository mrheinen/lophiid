package whois

import (
	"fmt"
	"log/slog"
	"loophid/pkg/database"
	"loophid/pkg/util"
	"sync"
	"time"
)

type WhoisManager interface {
	LookupIP(ip string) error
}

type CachedWhoisManager struct {
	dbClient    database.DatabaseClient
	whoisClient WhoisClientInterface
	ipCache     util.StringMapCache[bool]
	lookupMap   map[string]int
	bgChan      chan bool
	maxAttempts int
	mu          sync.Mutex
}

type WhoisClientInterface interface {
	Whois(domain string, servers ...string) (result string, err error)
}

func NewCachedWhoisManager(dbClient database.DatabaseClient, whoisClient WhoisClientInterface, cacheDuration time.Duration, maxAttempts int) *CachedWhoisManager {
	return &CachedWhoisManager{
		dbClient:    dbClient,
		whoisClient: whoisClient,
		// The int value in the map indicates how many times we have tried to lookup
		// the whois for that given IP.
		lookupMap:   make(map[string]int),
		bgChan:      make(chan bool),
		maxAttempts: maxAttempts,
		ipCache:     *util.NewStringMapCache[bool](cacheDuration),
	}
}

func (c *CachedWhoisManager) Start() {
	slog.Info("Starting Whois manager")
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

func (c *CachedWhoisManager) Stop() {
	slog.Info("Stopping Whois manager")
	c.bgChan <- true
}

// DoWhoisWork will perform the whois query for the IPs in the lookupMap.
func (c *CachedWhoisManager) DoWhoisWork() {
	var ips []string

	c.mu.Lock()
	for ip, lookupCount := range c.lookupMap {
		if lookupCount >= c.maxAttempts {
			slog.Warn("Removing IP from whois lookups. Exceeds # tries.", slog.String("ip", ip))
			delete(c.lookupMap, ip)
			continue
		}
		ips = append(ips, ip)
	}
	c.mu.Unlock()

	for _, ip := range ips {
		result, err := c.whoisClient.Whois(ip)
		if err != nil {
			slog.Warn("Failed to lookup whois for IP", slog.String("error", err.Error()))
			c.mu.Lock()
			c.lookupMap[ip] += 1
			c.mu.Unlock()
			continue
		}

		if _, err := c.dbClient.Insert(&database.Whois{IP: ip, Data: result}); err != nil {
			fmt.Printf("XXXX: %s\n", result)
			slog.Warn("Failed to store whois in database", slog.String("error", err.Error()))
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

func (c *CachedWhoisManager) LookupIP(ip string) error {
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

type FakeWhoisManager struct {
}

func (f *FakeWhoisManager) LookupIP(ip string) error {
	return nil
}
