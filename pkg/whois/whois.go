package whois

import (
	"fmt"
	"log/slog"
	"loophid/pkg/database"
	"loophid/pkg/util"
	"sync"
	"time"

	"github.com/likexian/whois"
)

type WhoisManager interface {
	LookupIP(ip string) error
}

type CachedWhoisManager struct {
	dbClient database.DatabaseClient
	ipCache  util.StringMapCache[bool]
	mu       sync.Mutex
}

func NewCachedWhoisManager(dbClient database.DatabaseClient) *CachedWhoisManager {
	return &CachedWhoisManager{
		dbClient: dbClient,
		ipCache:  *util.NewStringMapCache[bool](time.Hour * 12),
	}
}

func (c *CachedWhoisManager) LookupIP(ip string) error {

	c.mu.Lock()
	defer c.mu.Unlock()

	// If we have a cached entry for this IP then we can return
	// immediately and prevent doing a database query.
	_, err := c.ipCache.Get(ip)
	if err == nil {
		return nil
	}

	// Next check if there is an entry in the database already.
	_, err = c.dbClient.GetWhoisByIP(ip)
	if err == nil {
		return nil
	}

	result, err := whois.Whois(ip)
	if err != nil {
		return fmt.Errorf("doing whois: %w", err)
	}

	wRecord := &database.Whois{
		IP:   ip,
		Data: result,
	}

	if _, err := c.dbClient.Insert(wRecord); err != nil {
		return fmt.Errorf("doing whois insert: %w", err)
	}

	// We don't actually cache the results, we just cache the fact that we have
	// seen this IP.
	c.ipCache.Store(ip, true)
	slog.Debug("Added whois record for IP", slog.String("ip", ip))
	c.ipCache.CleanExpired()
	return nil
}

type FakeWhoisManager struct {
}

func (f *FakeWhoisManager) LookupIP(ip string) error {
	return nil
}
