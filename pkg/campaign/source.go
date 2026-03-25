// Lophiid distributed honeypot
// Copyright (C) 2025 Niels Heinen
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
package campaign

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"time"

	"lophiid/pkg/database"
	"lophiid/pkg/util/constants"
	whoisPkg "lophiid/pkg/whois"
)

// maxPreloadResults is the upper bound on records fetched during a single preload query.
const maxPreloadResults = 500000

// CampaignDataSource provides feature data for campaign clustering.
type CampaignDataSource interface {
	// Name returns a unique identifier for this source (used in config).
	Name() string
	// Enabled returns whether this source is active.
	Enabled() bool
	// Preload bulk-fetches all relevant data from the database for the given
	// time window and caches it in memory for fast enrichment lookups.
	// When windowEnd is zero, no upper bound is applied.
	Preload(ctx context.Context, windowStart, windowEnd time.Time) error
	// EnrichRequest populates feature fields on the EnrichedRequest from the
	// preloaded cache. Preload must be called before EnrichRequest.
	EnrichRequest(ctx context.Context, req *EnrichedRequest) error
}

// SourceRegistry holds all registered data sources.
type SourceRegistry struct {
	sources []CampaignDataSource
}

// NewSourceRegistry creates a SourceRegistry from configuration and a database client.
func NewSourceRegistry(cfg CampaignAgentConfig, db database.DatabaseClient) (*SourceRegistry, error) {
	reg := &SourceRegistry{}

	builders := map[string]func(SourceConfig) CampaignDataSource{
		constants.CampaignSourceRequest: func(sc SourceConfig) CampaignDataSource { return &RequestSource{enabled: sc.Enabled} },
		constants.CampaignSourceRequestDescription: func(sc SourceConfig) CampaignDataSource {
			return &RequestDescriptionSource{enabled: sc.Enabled, db: db}
		},
		constants.CampaignSourceWhois: func(sc SourceConfig) CampaignDataSource {
			maxPrefix := defaultMaxNetworkPrefix
			if v, ok := sc.Options["max_network_prefix"]; ok {
				if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
					maxPrefix = parsed
				}
			}
			return &WhoisSource{enabled: sc.Enabled, db: db, maxNetworkPrefix: maxPrefix}
		},
		constants.CampaignSourceP0f:       func(sc SourceConfig) CampaignDataSource { return &P0fSource{enabled: sc.Enabled, db: db} },
		constants.CampaignSourceIpEvent:   func(sc SourceConfig) CampaignDataSource { return &IpEventSource{enabled: sc.Enabled, db: db} },
		constants.CampaignSourceSession:   func(sc SourceConfig) CampaignDataSource { return &SessionSource{enabled: sc.Enabled, db: db} },
		constants.CampaignSourceDownloads: func(sc SourceConfig) CampaignDataSource { return &DownloadsSource{enabled: sc.Enabled, db: db} },
	}

	for name, sc := range cfg.Agent.Sources {
		builder, ok := builders[name]
		if !ok {
			return nil, fmt.Errorf("unknown source %q", name)
		}
		src := builder(sc)
		reg.sources = append(reg.sources, src)
		slog.Info("registered campaign source", slog.String("name", name), slog.Bool("enabled", sc.Enabled))
	}

	return reg, nil
}

// EnabledSources returns all enabled sources.
func (r *SourceRegistry) EnabledSources() []CampaignDataSource {
	var result []CampaignDataSource
	for _, s := range r.sources {
		if s.Enabled() {
			result = append(result, s)
		}
	}
	return result
}

// PreloadAll calls Preload on all enabled sources to bulk-fetch data for the
// given time window. This must be called before any EnrichAll/EnrichRequest calls.
// When windowEnd is zero, no upper bound is applied.
func (r *SourceRegistry) PreloadAll(ctx context.Context, windowStart, windowEnd time.Time) {
	for _, s := range r.sources {
		if !s.Enabled() {
			continue
		}
		if err := s.Preload(ctx, windowStart, windowEnd); err != nil {
			slog.Warn("source preload failed", slog.String("source", s.Name()), slog.String("error", err.Error()))
		}
	}
}

// EnrichAll calls EnrichRequest on all enabled sources for the given request.
func (r *SourceRegistry) EnrichAll(ctx context.Context, req *EnrichedRequest) error {
	for _, s := range r.sources {
		if !s.Enabled() {
			continue
		}
		if err := s.EnrichRequest(ctx, req); err != nil {
			slog.Warn("source enrichment failed", slog.String("source", s.Name()), slog.Int64("request_id", req.RequestID), slog.String("error", err.Error()))
			// Non-fatal: continue with other sources.
		}
	}
	return nil
}

// --- Cache value types ---

type cachedRequestDescription struct {
	AIApplication       string
	AIVulnerabilityType string
	AIMitreAttack       string
	AICVE               string
	AIMalicious         string
}

type cachedWhois struct {
	Country      string
	Rdap         []byte
	GeoIPASN     uint
	GeoIPASNOrg  string
	GeoIPCountry string
}

type cachedP0f struct {
	OsName    string
	OsVersion string
	LinkType  string
}

type cachedIpEvent struct {
	EventTypes string
	TotalCount int64
}

type cachedSession struct {
	BehaviorIsHuman   bool
	BehaviorHasBursts bool
	RequestCount      int64
}

type cachedDownload struct {
	SHA256sum           string
	VTAnalysisMalicious int64
	DetectedContentType string
	OriginalUrl         string
}

// --- Source implementations ---

// RequestSource extracts features from the base request model fields.
// These fields are already available on the request object and require no DB lookups.
type RequestSource struct {
	enabled bool
}

func (s *RequestSource) Name() string  { return constants.CampaignSourceRequest }
func (s *RequestSource) Enabled() bool { return s.enabled }

// Preload is a no-op for RequestSource since it has no external data.
func (s *RequestSource) Preload(_ context.Context, _, _ time.Time) error { return nil }

// EnrichRequest is a no-op. Fields (source_ip, cmp_hash, base_hash, uri,
// method, app_id) are set during request loading in the pipeline.
func (s *RequestSource) EnrichRequest(_ context.Context, _ *EnrichedRequest) error {
	return nil
}

// RequestDescriptionSource enriches with AI triage data from request_description.
type RequestDescriptionSource struct {
	enabled bool
	db      database.DatabaseClient
	cache   map[string]cachedRequestDescription // key: cmp_hash
}

func (s *RequestDescriptionSource) Name() string  { return constants.CampaignSourceRequestDescription }
func (s *RequestDescriptionSource) Enabled() bool { return s.enabled }

// Preload fetches all request descriptions in the given time window and caches
// them by cmp_hash for fast lookup during enrichment.
func (s *RequestDescriptionSource) Preload(_ context.Context, windowStart, windowEnd time.Time) error {
	query := fmt.Sprintf("created_at>%s", windowStart.Format(time.RFC3339))
	if !windowEnd.IsZero() {
		query += fmt.Sprintf(" created_at<%s", windowEnd.Format(time.RFC3339))
	}
	descs, err := s.db.SearchRequestDescription(0, maxPreloadResults, query)
	if err != nil {
		return fmt.Errorf("preloading request_descriptions: %w", err)
	}
	s.cache = make(map[string]cachedRequestDescription, len(descs))
	for _, d := range descs {
		if d.CmpHash == "" {
			continue
		}
		s.cache[d.CmpHash] = cachedRequestDescription{
			AIApplication:       d.AIApplication,
			AIVulnerabilityType: d.AIVulnerabilityType,
			AIMitreAttack:       d.AIMitreAttack,
			AICVE:               d.AICVE,
			AIMalicious:         d.AIMalicious,
		}
	}
	slog.Info("preloaded request descriptions", slog.Int("count", len(s.cache)))
	return nil
}

// EnrichRequest reads AI features from the preloaded cache by cmp_hash.
func (s *RequestDescriptionSource) EnrichRequest(_ context.Context, req *EnrichedRequest) error {
	cmpHash := req.Features.Get("cmp_hash")
	if cmpHash == "" {
		return nil
	}
	d, ok := s.cache[cmpHash]
	if !ok {
		return nil
	}
	req.Features.Set("ai_application", d.AIApplication)
	req.Features.Set("ai_vulnerability_type", d.AIVulnerabilityType)
	req.Features.Set("ai_mitre_attack", d.AIMitreAttack)
	req.Features.Set("ai_cve", d.AICVE)
	req.Features.Set("ai_malicious", d.AIMalicious)
	return nil
}

// defaultMaxNetworkPrefix is the default minimum prefix length for network_range matching.
// Networks larger than this (e.g. /8, /16) are skipped to avoid false positives
// from large cloud providers.
const defaultMaxNetworkPrefix = 20

// WhoisSource enriches with whois/RDAP data per source IP.
type WhoisSource struct {
	enabled          bool
	db               database.DatabaseClient
	maxNetworkPrefix int
	cache            map[string]cachedWhois // key: ip
}

func (s *WhoisSource) Name() string  { return constants.CampaignSourceWhois }
func (s *WhoisSource) Enabled() bool { return s.enabled }

// Preload fetches all whois records in the given time window and caches them
// by IP for fast lookup during enrichment.
func (s *WhoisSource) Preload(_ context.Context, windowStart, windowEnd time.Time) error {
	query := fmt.Sprintf("updated_at>%s", windowStart.Format(time.RFC3339))
	if !windowEnd.IsZero() {
		query += fmt.Sprintf(" updated_at<%s", windowEnd.Format(time.RFC3339))
	}
	results, err := s.db.SearchWhois(0, maxPreloadResults, query)
	if err != nil {
		return fmt.Errorf("preloading whois: %w", err)
	}
	s.cache = make(map[string]cachedWhois, len(results))
	for _, w := range results {
		if w.IP == "" {
			continue
		}
		s.cache[w.IP] = cachedWhois{
			Country:      w.Country,
			Rdap:         w.Rdap,
			GeoIPASN:     w.GeoIPASN,
			GeoIPASNOrg:  w.GeoIPASNOrg,
			GeoIPCountry: w.GeoIPCountry,
		}
	}
	slog.Info("preloaded whois records", slog.Int("count", len(s.cache)))
	return nil
}

// EnrichRequest reads whois data from the preloaded cache by source IP.
func (s *WhoisSource) EnrichRequest(_ context.Context, req *EnrichedRequest) error {
	if req.SourceIP == "" {
		return nil
	}
	w, ok := s.cache[req.SourceIP]
	if !ok {
		return nil
	}
	// "country" from RDAP is kept for backward compatibility; prefer
	// "geoip_country" from MaxMind which is more consistently populated.
	if w.Country != "" {
		req.Features.Set("country", w.Country)
	}
	if w.GeoIPASN != 0 {
		req.Features.Set("geoip_asn", strconv.FormatUint(uint64(w.GeoIPASN), 10))
	}
	if w.GeoIPASNOrg != "" {
		req.Features.Set("geoip_asn_org", w.GeoIPASNOrg)
	}
	if w.GeoIPCountry != "" {
		req.Features.Set("geoip_country", w.GeoIPCountry)
	}
	parser := whoisPkg.NewRdapParser(string(w.Rdap))
	if network, err := parser.GetNetwork(); err == nil {
		if network.Bits() >= s.maxNetworkPrefix {
			req.Features.Set("network_range", network.String())
		}
	}
	return nil
}

// P0fSource enriches with passive OS fingerprinting data per source IP.
type P0fSource struct {
	enabled bool
	db      database.DatabaseClient
	cache   map[string]cachedP0f // key: ip
}

func (s *P0fSource) Name() string  { return constants.CampaignSourceP0f }
func (s *P0fSource) Enabled() bool { return s.enabled }

// Preload fetches all p0f results in the given time window and caches them by IP.
func (s *P0fSource) Preload(_ context.Context, windowStart, windowEnd time.Time) error {
	query := fmt.Sprintf("last_seen_time>%s", windowStart.Format(time.RFC3339))
	if !windowEnd.IsZero() {
		query += fmt.Sprintf(" last_seen_time<%s", windowEnd.Format(time.RFC3339))
	}
	results, err := s.db.SearchP0fResult(0, maxPreloadResults, query)
	if err != nil {
		return fmt.Errorf("preloading p0f: %w", err)
	}
	s.cache = make(map[string]cachedP0f, len(results))
	for _, r := range results {
		if r.IP == "" {
			continue
		}
		s.cache[r.IP] = cachedP0f{
			OsName:    r.OsName,
			OsVersion: r.OsVersion,
			LinkType:  r.LinkType,
		}
	}
	slog.Info("preloaded p0f results", slog.Int("count", len(s.cache)))
	return nil
}

// EnrichRequest reads p0f data from the preloaded cache by source IP.
func (s *P0fSource) EnrichRequest(_ context.Context, req *EnrichedRequest) error {
	if req.SourceIP == "" {
		return nil
	}
	r, ok := s.cache[req.SourceIP]
	if !ok {
		return nil
	}
	req.Features.Set("os_name", r.OsName)
	req.Features.Set("os_version", r.OsVersion)
	req.Features.Set("link_type", r.LinkType)
	return nil
}

// IpEventSource enriches with IP event history per source IP.
type IpEventSource struct {
	enabled bool
	db      database.DatabaseClient
	cache   map[string]cachedIpEvent // key: ip
}

func (s *IpEventSource) Name() string  { return constants.CampaignSourceIpEvent }
func (s *IpEventSource) Enabled() bool { return s.enabled }

// Preload fetches all IP events in the given time window, aggregates types and
// counts per IP, and caches the result.
func (s *IpEventSource) Preload(_ context.Context, windowStart, windowEnd time.Time) error {
	query := fmt.Sprintf("first_seen_at>%s", windowStart.Format(time.RFC3339))
	if !windowEnd.IsZero() {
		query += fmt.Sprintf(" first_seen_at<%s", windowEnd.Format(time.RFC3339))
	}
	events, err := s.db.SearchEvents(0, maxPreloadResults, query)
	if err != nil {
		return fmt.Errorf("preloading ip_events: %w", err)
	}

	// Aggregate per IP.
	ipTypes := make(map[string]map[string]bool)
	ipCounts := make(map[string]int64)
	for _, e := range events {
		if e.IP == "" {
			continue
		}
		if ipTypes[e.IP] == nil {
			ipTypes[e.IP] = make(map[string]bool)
		}
		ipTypes[e.IP][e.Type] = true
		ipCounts[e.IP] += e.Count
	}

	s.cache = make(map[string]cachedIpEvent, len(ipTypes))
	for ip, types := range ipTypes {
		typeStr := ""
		for t := range types {
			if typeStr != "" {
				typeStr += ","
			}
			typeStr += t
		}
		s.cache[ip] = cachedIpEvent{
			EventTypes: typeStr,
			TotalCount: ipCounts[ip],
		}
	}
	slog.Info("preloaded ip events", slog.Int("count", len(s.cache)))
	return nil
}

// EnrichRequest reads aggregated event data from the preloaded cache by source IP.
func (s *IpEventSource) EnrichRequest(_ context.Context, req *EnrichedRequest) error {
	if req.SourceIP == "" {
		return nil
	}
	e, ok := s.cache[req.SourceIP]
	if !ok {
		return nil
	}
	req.Features.Set("event_type", e.EventTypes)
	req.Features.Set("event_count", strconv.FormatInt(e.TotalCount, 10))
	return nil
}

// SessionSource enriches with session behavior data.
type SessionSource struct {
	enabled bool
	db      database.DatabaseClient
	cache   map[int64]cachedSession // key: session id
}

func (s *SessionSource) Name() string  { return constants.CampaignSourceSession }
func (s *SessionSource) Enabled() bool { return s.enabled }

// Preload fetches all sessions in the given time window and caches them by ID.
func (s *SessionSource) Preload(_ context.Context, windowStart, windowEnd time.Time) error {
	query := fmt.Sprintf("started_at>%s", windowStart.Format(time.RFC3339))
	if !windowEnd.IsZero() {
		query += fmt.Sprintf(" started_at<%s", windowEnd.Format(time.RFC3339))
	}
	sessions, err := s.db.SearchSession(0, maxPreloadResults, query)
	if err != nil {
		return fmt.Errorf("preloading sessions: %w", err)
	}
	s.cache = make(map[int64]cachedSession, len(sessions))
	for _, sess := range sessions {
		s.cache[sess.ID] = cachedSession{
			BehaviorIsHuman:   sess.BehaviorIsHuman,
			BehaviorHasBursts: sess.BehaviorHasBursts,
			RequestCount:      sess.RequestCount,
		}
	}
	slog.Info("preloaded sessions", slog.Int("count", len(s.cache)))
	return nil
}

// EnrichRequest reads session data from the preloaded cache by session ID.
func (s *SessionSource) EnrichRequest(_ context.Context, req *EnrichedRequest) error {
	if req.SessionID == 0 {
		return nil
	}
	sess, ok := s.cache[req.SessionID]
	if !ok {
		return nil
	}
	req.Features.Set("behavior_is_human", strconv.FormatBool(sess.BehaviorIsHuman))
	req.Features.Set("behavior_has_bursts", strconv.FormatBool(sess.BehaviorHasBursts))
	req.Features.Set("request_count", strconv.FormatInt(sess.RequestCount, 10))
	return nil
}

// DownloadsSource enriches with download/malware data per request.
type DownloadsSource struct {
	enabled bool
	db      database.DatabaseClient
	cache   map[int64]cachedDownload // key: request_id
}

func (s *DownloadsSource) Name() string  { return constants.CampaignSourceDownloads }
func (s *DownloadsSource) Enabled() bool { return s.enabled }

// Preload fetches all downloads in the given time window and caches them by
// request_id.
func (s *DownloadsSource) Preload(_ context.Context, windowStart, windowEnd time.Time) error {
	query := fmt.Sprintf("created_at>%s", windowStart.Format(time.RFC3339))
	if !windowEnd.IsZero() {
		query += fmt.Sprintf(" created_at<%s", windowEnd.Format(time.RFC3339))
	}
	downloads, err := s.db.SearchDownloads(0, maxPreloadResults, query)
	if err != nil {
		return fmt.Errorf("preloading downloads: %w", err)
	}
	s.cache = make(map[int64]cachedDownload, len(downloads))
	for _, d := range downloads {
		s.cache[d.RequestID] = cachedDownload{
			SHA256sum:           d.SHA256sum,
			VTAnalysisMalicious: d.VTAnalysisMalicious,
			DetectedContentType: d.DetectedContentType,
			OriginalUrl:         d.OriginalUrl,
		}
	}
	slog.Info("preloaded downloads", slog.Int("count", len(s.cache)))
	return nil
}

// EnrichRequest reads download data from the preloaded cache by request ID.
func (s *DownloadsSource) EnrichRequest(_ context.Context, req *EnrichedRequest) error {
	d, ok := s.cache[req.RequestID]
	if !ok {
		return nil
	}
	req.Features.Set("download_sha256_hash", d.SHA256sum)
	req.Features.Set("vt_malicious_count", strconv.FormatInt(d.VTAnalysisMalicious, 10))
	req.Features.Set("content_type", d.DetectedContentType)
	req.Features.Set("download_url", d.OriginalUrl)
	if parsed, err := url.Parse(d.OriginalUrl); err == nil && parsed.Hostname() != "" {
		req.Features.Set("download_url_hostname", parsed.Hostname())
	}
	return nil
}
