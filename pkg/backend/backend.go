// Lophiid distributed honeypot
// Copyright (C) 2026 Niels Heinen
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
package backend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"lophiid/backend_service"
	"lophiid/pkg/alerting"
	"lophiid/pkg/analysis"
	"lophiid/pkg/backend/auth"
	"lophiid/pkg/backend/extractors"
	"lophiid/pkg/backend/ratelimit"
	"lophiid/pkg/backend/responder"
	"lophiid/pkg/backend/session"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/javascript"
	"lophiid/pkg/llm/interpreter"
	"lophiid/pkg/triage/describer"
	"lophiid/pkg/triage/preprocess"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"lophiid/pkg/util/decoding"
	"lophiid/pkg/util/logutil"
	"lophiid/pkg/util/shell"
	"lophiid/pkg/util/templator"
	"lophiid/pkg/vt"
	"lophiid/pkg/whois"

	"github.com/vingarcia/ksql"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// User agent to use for downloading.
const userAgent = "Wget/1.13.4 (linux-gnu)"
const maxUrlsToExtractForDownload = 15
const maxPingsToExtract = 5
const maxSqlDelayMs = 10000

// Debug header names for requests from debug IPs.
const DebugHeaderRequestID = "X-Lophiid-Request-ID"
const DebugHeaderSessionID = "X-Lophiid-Session-ID"

// FallbackContent is used for cases where we are not able to provide any other
// content (e.g. due to an error).
const FallbackContent = "<html></html>"

type Option func(*BackendServer)

// WithCodeInterpreter sets the code interpreter for the backend server.
func WithCodeInterpreter(ci interpreter.CodeInterpreterInterface) Option {
	return func(s *BackendServer) {
		s.codeInterpreter = ci
	}
}

// WithPreprocessor sets the preprocessor for the backend server.
func WithPreprocessor(p preprocess.PreProcessInterface) Option {
	return func(s *BackendServer) {
		s.preprocessor = p
	}
}

// WithSessionManager sets the session manager for the backend server.
func WithSessionManager(sm session.SessionManager) Option {
	return func(s *BackendServer) {
		s.sessionMgr = sm
	}
}

// WithDescriber sets the describer client for the backend server.
func WithDescriber(d describer.DescriberClient) Option {
	return func(s *BackendServer) {
		s.describer = d
	}
}

// WithIpEventManager sets the IP event manager for the backend server.
func WithIpEventManager(m analysis.IpEventManager) Option {
	return func(s *BackendServer) {
		s.ipEventManager = m
	}
}

// WithResponder sets the LLM responder for the backend server.
func WithResponder(r responder.Responder) Option {
	return func(s *BackendServer) {
		s.llmResponder = r
	}
}

// WithJavascriptRunner sets the JavaScript runner for the backend server.
func WithJavascriptRunner(jr javascript.JavascriptRunner) Option {
	return func(s *BackendServer) {
		s.jRunner = jr
	}
}

// WithAlertManager sets the alert manager for the backend server.
func WithAlertManager(am *alerting.AlertManager) Option {
	return func(s *BackendServer) {
		s.alertMgr = am
	}
}

// WithVTManager sets the VirusTotal manager for the backend server.
func WithVTManager(vtm vt.VTManager) Option {
	return func(s *BackendServer) {
		s.vtMgr = vtm
	}
}

// WithWhoisManager sets the WHOIS/RDAP manager for the backend server.
func WithWhoisManager(wm whois.RdapManager) Option {
	return func(s *BackendServer) {
		s.whoisMgr = wm
	}
}

// WithQueryRunner sets the query runner for the backend server.
func WithQueryRunner(qr QueryRunner) Option {
	return func(s *BackendServer) {
		s.qRunner = qr
	}
}

// BackendCaches holds all the caches used by the BackendServer.
type BackendCaches struct {
	sessionCache            *util.StringMapCache[models.ContentRule]
	downloadsCache          *util.StringMapCache[time.Time]
	downloadsIPCounts       *util.StringMapCache[int64]
	uploadsIPCounts         *util.StringMapCache[int64]
	pingsCache              *util.StringMapCache[time.Time]
	hCache                  *util.StringMapCache[models.Honeypot]
	payloadCmpHashCache     *util.StringMapCache[struct{}]
	consecutivePayloadCache *util.StringMapCache[map[string]string]
}

// NewBackendCaches creates and starts all caches used by the BackendServer.
func NewBackendCaches(config Config) *BackendCaches {
	sCache := util.NewStringMapCache[models.ContentRule]("content_cache", config.Backend.Advanced.ContentCacheDuration)

	dCache := util.NewStringMapCache[time.Time]("download_cache", config.Backend.Advanced.DownloadCacheDuration)

	dIPCount := util.NewStringMapCache[int64]("download_ip_counters", config.Backend.Advanced.DownloadIPCountersDuration)
	dIPCount.Start()

	uIPCount := util.NewStringMapCache[int64]("upload_ip_counters", config.Backend.Advanced.MaxUploadsPerIPWindow)
	uIPCount.Start()

	pCache := util.NewStringMapCache[time.Time]("ping_cache", config.Backend.Advanced.PingCacheDuration)

	hCache := util.NewStringMapCache[models.Honeypot]("honeypot_cache", config.Backend.Advanced.HoneypotCacheDuration)
	hCache.Start()

	plCache := util.NewStringMapCache[struct{}]("payload_cmp_hash_cache", config.Backend.Advanced.PayloadCmpHashDuration)
	plCache.Start()

	cpCache := util.NewStringMapCache[map[string]string]("consecutive_payload_cache", config.Backend.Advanced.ConsecutivePayloadDuration)
	cpCache.Start()

	return &BackendCaches{
		sessionCache:            sCache,
		downloadsCache:          dCache,
		downloadsIPCounts:       dIPCount,
		uploadsIPCounts:         uIPCount,
		pingsCache:              pCache,
		hCache:                  hCache,
		payloadCmpHashCache:     plCache,
		consecutivePayloadCache: cpCache,
	}
}

type ReqQueueEntry struct {
	req        *models.Request
	rule       models.ContentRule
	eCollector *extractors.ExtractorCollection
}

type BackendServer struct {
	backend_service.BackendServiceServer
	dbClient            database.DatabaseClient
	jRunner             javascript.JavascriptRunner
	qRunner             QueryRunner
	qRunnerChan         chan bool
	vtMgr               vt.VTManager
	whoisMgr            whois.RdapManager
	alertMgr            *alerting.AlertManager
	safeRules           *SafeRules
	maintenanceChan     chan bool
	reqsProcessChan     chan bool
	reqsQueue           chan ReqQueueEntry
	sessionCache        *util.StringMapCache[models.ContentRule]
	downloadQueue       map[string][]backend_service.CommandDownloadFile
	downloadQueueMu     sync.Mutex
	downloadsCache      *util.StringMapCache[time.Time]
	downloadsIPCounts   *util.StringMapCache[int64]
	downloadsIPCountsMu sync.Mutex
	uploadsIPCounts     *util.StringMapCache[int64]
	pingQueue           map[string][]backend_service.CommandPingAddress
	pingQueueMu         sync.Mutex
	pingsCache          *util.StringMapCache[time.Time]
	metrics             *BackendMetrics
	rateLimiters        []ratelimit.RateLimiter
	ipEventManager      analysis.IpEventManager
	config              Config
	llmResponder        responder.Responder
	sessionMgr          session.SessionManager
	describer           describer.DescriberClient
	preprocessor        preprocess.PreProcessInterface
	codeInterpreter     interpreter.CodeInterpreterInterface
	hCache              *util.StringMapCache[models.Honeypot]
	HpDefaultContentID  int
	// payloadCmpHashCache is used to cache cmp_hash for requests to allow similar
	// requests to be handled by the triage process.
	payloadCmpHashCache *util.StringMapCache[struct{}]
	// payloadSessionCache uses the session ID, cmp_hash and attacked parameter
	// as key. The value is a map where each key is a hash of the payload with the
	// cmp_hash as value.
	payloadSessionCache *util.StringMapCache[map[string]string]
}

// NewBackendServer creates a new instance of the backend server.
func NewBackendServer(c database.DatabaseClient, metrics *BackendMetrics, rateLimiters []ratelimit.RateLimiter, config Config, opts ...Option) *BackendServer {
	caches := NewBackendCaches(config)

	be := &BackendServer{
		dbClient:            c,
		qRunnerChan:         make(chan bool),
		safeRules:           &SafeRules{},
		maintenanceChan:     make(chan bool),
		reqsProcessChan:     make(chan bool),
		reqsQueue:           make(chan ReqQueueEntry, config.Backend.Advanced.RequestsQueueSize),
		downloadQueue:       make(map[string][]backend_service.CommandDownloadFile),
		downloadsCache:      caches.downloadsCache,
		uploadsIPCounts:     caches.uploadsIPCounts,
		downloadsIPCounts:   caches.downloadsIPCounts,
		downloadsIPCountsMu: sync.Mutex{},
		pingQueue:           make(map[string][]backend_service.CommandPingAddress),
		pingsCache:          caches.pingsCache,
		sessionCache:        caches.sessionCache,
		metrics:             metrics,
		config:              config,
		rateLimiters:        rateLimiters,
		hCache:              caches.hCache,
		HpDefaultContentID:  config.Backend.Advanced.HoneypotDefaultContentID,
		payloadCmpHashCache: caches.payloadCmpHashCache,
		payloadSessionCache: caches.consecutivePayloadCache,
	}

	for _, opt := range opts {
		opt(be)
	}

	return be
}

// isDebugIP checks if the given IP is in the list of debug networks configured
// in the backend. When true, responses should include debug headers.
// Debug IPs should be specified in CIDR notation (e.g., "192.168.1.0/24" for a
// network or "10.0.0.1/32" for a single IP).
func (s *BackendServer) isDebugIP(ip string) bool {
	requestIP := net.ParseIP(ip)
	if requestIP == nil {
		return false
	}
	for _, debugCIDR := range s.config.Backend.Advanced.DebugIPs {
		_, ipNet, err := net.ParseCIDR(debugCIDR)
		if err != nil {
			continue
		}
		if ipNet.Contains(requestIP) {
			return true
		}
	}
	return false
}

func (s *BackendServer) ScheduleDownloadOfPayload(sourceIP string, honeypotIP string, originalUrl string, targetIP string, targetUrl string, hostHeader string, requestID int64) bool {
	_, err := s.downloadsCache.Get(originalUrl)
	if err == nil {
		slog.Debug("skipping download as it is in the cache", slog.Int64("request_id", requestID), slog.String("url", originalUrl))
		return false
	}

	s.downloadsIPCountsMu.Lock()
	defer s.downloadsIPCountsMu.Unlock()

	val, err := s.downloadsIPCounts.Get(sourceIP)
	if err != nil {
		s.downloadsIPCounts.Store(sourceIP, 1)
	} else {
		*val = *val + 1
		s.downloadsIPCounts.Replace(sourceIP, *val)
		if *val > int64(s.config.Backend.Advanced.MaxDownloadsPerIP) {
			slog.Debug("skipping download as IP is over the limit", slog.Int64("request_id", requestID), slog.String("url", originalUrl), slog.String("ip", sourceIP))
			return false
		}
	}

	slog.Debug("adding URL to cache", slog.Int64("request_id", requestID), slog.String("original_url", originalUrl))
	s.downloadsCache.Store(originalUrl, time.Now())

	s.downloadQueueMu.Lock()
	s.downloadQueue[honeypotIP] = append(s.downloadQueue[honeypotIP], backend_service.CommandDownloadFile{
		Url:         targetUrl,
		HostHeader:  hostHeader,
		RequestId:   requestID,
		UserAgent:   userAgent,
		OriginalUrl: originalUrl,
		Ip:          targetIP,
		SourceIp:    sourceIP,
	})
	s.downloadQueueMu.Unlock()
	return true
}

func (s *BackendServer) SchedulePingOfAddress(honeypotIP string, address string, count int64, requestID int64) bool {

	_, err := s.pingsCache.Get(address)
	if err == nil {
		slog.Debug("skipping ping as it is in the cache", slog.Int64("request_id", requestID), slog.String("address", address))
		return false
	}

	slog.Debug("scheduling ping address", slog.Int64("request_id", requestID), slog.String("honeypot_ip", honeypotIP), slog.String("address", address))
	s.pingsCache.Store(address, time.Now())

	s.pingQueueMu.Lock()
	s.pingQueue[honeypotIP] = append(s.pingQueue[honeypotIP], backend_service.CommandPingAddress{
		RequestId: requestID,
		Address:   address,
		Count:     count,
	})
	s.pingQueueMu.Unlock()
	return true
}

// ProbeRequestToDatabaseRequest transforms aHandleProbeRequest to a
// models.Request.
func (s *BackendServer) ProbeRequestToDatabaseRequest(req *backend_service.HandleProbeRequest) (*models.Request, error) {
	sReq := models.Request{
		TimeReceived:  time.Unix(req.GetRequest().GetTimeReceived(), 0),
		Proto:         req.GetRequest().GetProto(),
		Method:        req.GetRequest().GetMethod(),
		Uri:           req.GetRequestUri(),
		Path:          req.GetRequest().GetParsedUrl().GetPath(),
		Query:         req.GetRequest().GetParsedUrl().GetRawQuery(),
		Port:          req.GetRequest().GetParsedUrl().GetPort(),
		ContentLength: req.GetRequest().GetContentLength(),
		Raw:           req.GetRequest().GetRaw(),
		HoneypotIP:    req.GetRequest().GetHoneypotIp(),
	}

	if req.GetRequest().Body != nil {
		sReq.Body = req.GetRequest().GetBody()
	} else {
		sReq.Body = []byte("")
	}

	remoteAddrHost, remoteAddrPort, err := net.SplitHostPort(req.GetRequest().GetRemoteAddress())
	if err != nil {
		return nil, fmt.Errorf("unable to parse host:port : %w", err)
	}

	sReq.SourceIP = remoteAddrHost
	port, err := strconv.Atoi(remoteAddrPort)
	if err != nil {
		return nil, fmt.Errorf("cannot parse IP: %s", err)
	}
	sReq.SourcePort = int64(port)

	for _, h := range req.GetRequest().GetHeader() {
		switch strings.ToLower(h.Key) {
		case "referer":
			sReq.Referer = h.Value
		case "user-agent":
			sReq.UserAgent = h.Value
		case "content-type":
			sReq.ContentType = h.Value
		}

		sReq.Headers = append(sReq.Headers, fmt.Sprintf("%s: %s", h.Key, h.Value))
	}

	hash, err := database.GetHashFromStaticRequestFields(&sReq)
	if err == nil {
		sReq.BaseHash = hash
	}

	hash, err = database.GetSameRequestHash(&sReq)
	if err == nil {
		sReq.CmpHash = hash
	}

	sReq.TriagePayloadType = constants.TriagePayloadTypeUnknown
	return &sReq, nil
}

// AddLLMResponseToContent adds the LLM response to the content.
func AddLLMResponseToContent(content *models.Content, llmResponse string) string {
	template := string(content.Data)
	if !strings.Contains(template, constants.LLMReplacementTag) {
		template = fmt.Sprintf("%s\n%s", template, constants.LLMReplacementTag)
	}

	return strings.Replace(template, constants.LLMReplacementTag, llmResponse, 1)
}

func (s *BackendServer) UpdateSessionWithRule(ip string, session *models.Session, rule *models.ContentRule) {
	session.LastRuleServed = *rule
	session.ServedRuleWithContent(rule.ID, rule.ContentID)
	if err := s.sessionMgr.UpdateCachedSession(ip, session); err != nil {
		slog.Error("error updating session", slog.Int64("session_id", session.ID), slog.String("ip", ip), slog.String("error", err.Error()))
	}
}

// SendPingStatus is called by the agent to notify the backend about the status
// of a ping test.
func (s *BackendServer) SendPingStatus(ctx context.Context, req *backend_service.SendPingStatusRequest) (*backend_service.SendPingStatusResponse, error) {
	hp, ok := auth.GetHoneypotMetadata(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authentication found")
	}

	outcome := constants.IpEventSubTypeSuccess
	if req.GetCount() != req.GetPacketsSent() || req.GetPacketsSent() != req.GetPacketsReceived() {
		outcome = constants.IpEventSubTypeFailure
	}

	evt := &models.IpEvent{
		IP:            req.GetAddress(),
		Type:          constants.IpEventPing,
		Subtype:       outcome,
		Details:       fmt.Sprintf("%d/%d sent/recv - rtt %d/%d/%d avg/min/max", req.GetPacketsSent(), req.GetPacketsReceived(), req.GetAverageRttMs(), req.GetMinRttMs(), req.GetMaxRttMs()),
		Source:        constants.IpEventSourceAgent,
		RequestID:     req.GetRequestId(),
		HoneypotIP:    hp.IP,
		SourceRefType: constants.IpEventRefTypeNone,
	}

	slog.Info("ping status", slog.Int64("request_id", req.GetRequestId()), slog.String("ip", req.GetAddress()), slog.String("outcome", outcome), slog.Int64("packets_sent", req.GetPacketsSent()), slog.Int64("packets_received", req.GetPacketsReceived()), slog.Int64("average_rtt", req.GetAverageRttMs()), slog.Int64("min_rtt", req.GetMinRttMs()), slog.Int64("max_rtt", req.GetMaxRttMs()))
	s.ipEventManager.AddEvent(evt)

	return &backend_service.SendPingStatusResponse{}, nil
}

// SendStatus receives status information from honeypots and sends commands back
// in response. This is not authenticated!
func (s *BackendServer) SendStatus(ctx context.Context, req *backend_service.StatusRequest) (*backend_service.StatusResponse, error) {
	// Right now we just print an error because it's actually useful to still
	// update the database with this honeypots information.
	if err := util.IsLophiidVersionCompatible(req.GetVersion(), constants.LophiidVersion); err != nil {
		slog.Error("backend and honeypot version are incompatible", slog.String("backend_version", constants.LophiidVersion), slog.String("honeypot_version", req.GetVersion()), slog.String("error", err.Error()))
	}

	dms, err := s.dbClient.SearchHoneypots(0, 1, fmt.Sprintf("ip:%s", req.GetIp()))
	if err != nil {
		slog.Error("error finding honeypot", slog.String("error", err.Error()), slog.String("honeypot", req.GetIp()))
		return &backend_service.StatusResponse{}, status.Errorf(codes.NotFound, "error doing lookup")
	}
	if len(dms) == 0 {
		hp := &models.Honeypot{
			IP:               req.GetIp(),
			Version:          req.GetVersion(),
			LastCheckin:      time.Now(),
			DefaultContentID: int64(s.HpDefaultContentID),
		}

		hp.Ports = append(hp.Ports, req.GetListenPort()...)
		hp.SSLPorts = append(hp.Ports, req.GetListenPortSsl()...)

		_, err := s.dbClient.Insert(hp)

		if err != nil {
			slog.Error("error inserting honeypot", slog.String("error", err.Error()))
			return &backend_service.StatusResponse{}, status.Errorf(codes.Unavailable, "error inserting honeypot: %s", err)
		}
		slog.Info("status: added honeypot ", slog.String("ip", req.GetIp()))
	} else {
		dms[0].LastCheckin = time.Now()
		dms[0].Version = req.GetVersion()

		dms[0].Ports = req.GetListenPort()
		dms[0].SSLPorts = req.GetListenPortSsl()

		if err := s.dbClient.Update(&dms[0]); err != nil {
			return &backend_service.StatusResponse{}, status.Errorf(codes.Unavailable, "error updating honeypot: %s", err)
		}
		slog.Debug("status: updated honeypot ", slog.String("ip", req.GetIp()))
	}

	// Check if there are any downloads scheduled for this honeypot.
	s.downloadQueueMu.Lock()
	defer s.downloadQueueMu.Unlock()
	cmds, ok := s.downloadQueue[req.GetIp()]
	if ok && len(cmds) > 0 {
		ret := &backend_service.StatusResponse{}
		for idx := range cmds {
			ret.Command = append(ret.Command, &backend_service.Command{
				Command: &backend_service.Command_DownloadCmd{
					DownloadCmd: &cmds[idx],
				},
			})
		}

		delete(s.downloadQueue, req.GetIp())
		return ret, nil
	}

	// Next check if a ping is desired.
	s.pingQueueMu.Lock()
	defer s.pingQueueMu.Unlock()
	pcmds, ok := s.pingQueue[req.GetIp()]
	if ok && len(pcmds) > 0 {
		ret := &backend_service.StatusResponse{}
		for idx := range pcmds {
			slog.Debug("sending ping command", slog.String("address", pcmds[idx].GetAddress()))
			ret.Command = append(ret.Command, &backend_service.Command{
				Command: &backend_service.Command_PingCmd{
					PingCmd: &pcmds[idx],
				},
			})
		}

		delete(s.pingQueue, req.GetIp())
		return ret, nil
	}

	return &backend_service.StatusResponse{}, nil
}

func (s *BackendServer) SendSourceContext(ctx context.Context, req *backend_service.SendSourceContextRequest) (*backend_service.SendSourceContextResponse, error) {

	_, ok := auth.GetHoneypotMetadata(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authentication found")
	}

	ret := &backend_service.SendSourceContextResponse{}

	switch c := req.Context.(type) {
	case *backend_service.SendSourceContextRequest_P0FResult:
		if _, err := s.HandleP0fResult(req.GetSourceIp(), c.P0FResult); err != nil {
			return ret, status.Errorf(codes.Internal, "handling p0f result: %s", err)
		}

	default:
		return ret, status.Error(codes.FailedPrecondition, "unknown context type")
	}
	return ret, nil
}

// HandleP0fResult checks the database to see if a p0f result with a max age of
// 24 hours is already present and inserts it if not. Returns a bool indicating
// whether the record was added.
func (s *BackendServer) HandleP0fResult(ip string, res *backend_service.P0FResult) (bool, error) {
	pr := models.P0fResult{
		IP:               ip,
		FirstSeen:        time.Unix(int64(res.GetFirstSeen()), 0),
		LastSeen:         time.Unix(int64(res.GetLastSeen()), 0),
		LastNatDetection: time.Unix(int64(res.GetLastNatDetection()), 0),
		LastOsChange:     time.Unix(int64(res.GetLastOsChange()), 0),
		TotalCount:       int64(res.GetTotalCount()),
		UptimeMinutes:    int64(res.GetUptimeMinutes()),
		UptimeDays:       int64(res.GetUptimeDays()),
		Distance:         int64(res.GetDistance()),
		OsMatchQuality:   int64(res.GetOsMatchQuality()),
		OsName:           res.GetOsName(),
		OsVersion:        res.GetOsVersion(),
		HttpName:         res.GetHttpName(),
		HttpFlavor:       res.GetHttpFlavor(),
		LinkType:         res.GetLinkType(),
		Language:         res.GetLanguage(),
	}

	// Only check the last 24 hours as all other results are considered stale. If
	// there is no entry then we will add a new one.
	_, err := s.dbClient.GetP0fResultByIP(ip, " AND created_at BETWEEN NOW() - INTERVAL '24 HOURS' AND NOW()")
	if err == nil {
		return false, nil
	}

	if !errors.Is(err, ksql.ErrRecordNotFound) {
		return false, fmt.Errorf("while fetching p0f result: %w", err)
	}

	if _, err = s.dbClient.Insert(&pr); err != nil {
		return false, fmt.Errorf("while inserting p0f result: %w (result: %+v)", err, pr)
	}
	return true, nil
}

// getCachedHoneypot returns the honeypot with the given IP from the cache.
func (s *BackendServer) getCachedHoneypot(hpIP string) (*models.Honeypot, error) {
	// Check the cache.
	hp, err := s.hCache.Get(hpIP)
	if err == nil {
		return hp, nil
	}

	// Not in cache so fetch from the database
	hps, err := s.dbClient.SearchHoneypots(0, 1, fmt.Sprintf("ip:%s", hpIP))
	if err != nil {
		return nil, fmt.Errorf("error finding honeypot: %w", err)
	}

	if len(hps) == 1 {
		// Update the cache.
		s.hCache.Store(hpIP, hps[0])
		return &hps[0], nil
	}

	return nil, fmt.Errorf("could not find honeypot: %s", hpIP)
}

func (s *BackendServer) MaybeExtractLinksFromPayload(fileContent []byte, dInfo models.Download) bool {

	// Check against the reported and detected content type to see if we want to
	// parse this file for URLs.
	if !HasParseableContent(dInfo.UsedUrl, dInfo.ContentType) &&
		!HasParseableContent(dInfo.UsedUrl, dInfo.DetectedContentType) {
		return false
	}

	// Expand the file if possible.
	exp := shell.NewExpander()
	itr := shell.ScriptIterator{}
	itr.FromBuffer(fileContent)

	expandedContent := exp.Expand(&itr)

	linksMap := make(map[string]struct{})
	lx := extractors.NewURLExtractor(linksMap)
	lx.ParseString(string(fileContent))

	beforeLen := len(linksMap)
	lx.ParseString(strings.Join(expandedContent, "\n"))

	if len(linksMap) > beforeLen {
		slog.Debug("extracted more links from expanded payload", slog.Int("before", beforeLen), slog.Int("after", len(linksMap)))
	}

	if len(linksMap) > maxUrlsToExtractForDownload {
		slog.Warn("content got too many URLs", slog.String("url", dInfo.OriginalUrl), slog.Int("url_count", len(linksMap)))
		return false
	}

	for k := range linksMap {
		u, err := url.Parse(k)
		if err != nil {
			slog.Debug("couldnt parse content download link", slog.String("error", err.Error()))
			continue
		}

		host := u.Host
		if strings.Contains(host, ":") {
			host, _, _ = net.SplitHostPort(u.Host)
		}

		dHost := dInfo.Host
		if strings.Contains(dHost, ":") {
			dHost, _, _ = net.SplitHostPort(dHost)
		}

		if host == dHost {
			slog.Info("Downloading link from payload", slog.String("url", k))

			ipBasedUrl, ip, hostHeader, err := ConvertURLToIPBased(k)
			if err != nil {
				slog.Warn("error converting URL", slog.String("error", err.Error()))
				continue
			}

			s.ScheduleDownloadOfPayload(dInfo.SourceIP, dInfo.HoneypotIP, k, ip, ipBasedUrl, hostHeader, dInfo.RequestID)
		}
	}
	return true
}

func (s *BackendServer) HandleUploadFile(ctx context.Context, req *backend_service.UploadFileRequest) (*backend_service.UploadFileResponse, error) {
	_, ok := auth.GetHoneypotMetadata(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authentication found")
	}

	rpcStartTime := time.Now()
	retResponse := &backend_service.UploadFileResponse{}

	slog.Debug("Got upload from URL", slog.Int64("request_id", req.RequestId), slog.String("url", req.GetInfo().GetOriginalUrl()))
	// Store the download information in the database.
	dInfo := models.Download{}
	dInfo.SHA256sum = fmt.Sprintf("%x", sha256.Sum256(req.GetInfo().GetData()))
	dInfo.UsedUrl = req.GetInfo().GetUrl()
	dInfo.Host = req.GetInfo().GetHostHeader()
	dInfo.ContentType = req.GetInfo().GetContentType()
	dInfo.DetectedContentType = req.GetInfo().GetDetectedContentType()
	dInfo.OriginalUrl = req.GetInfo().GetOriginalUrl()
	dInfo.RequestID = req.RequestId
	dInfo.SourceIP = req.GetInfo().GetSourceIp()
	dInfo.IP = req.GetInfo().GetIp()
	dInfo.HoneypotIP = req.GetInfo().GetHoneypotIp()
	dInfo.LastRequestID = req.RequestId
	dInfo.TimesSeen = 1
	dInfo.LastSeenAt = time.Now()
	dInfo.YaraStatus = "PENDING"
	dInfo.RawHttpResponse = req.GetInfo().GetRawHttpResponse()

	s.metrics.downloadResponseTime.Observe(req.GetInfo().GetDurationSec())

	dms, err := s.dbClient.SearchDownloads(0, 1, fmt.Sprintf("sha256sum:%s", dInfo.SHA256sum))
	if len(dms) == 1 {
		dm := dms[0]
		dm.TimesSeen = dm.TimesSeen + 1
		dm.LastRequestID = req.RequestId
		dm.LastSeenAt = time.Now()
		// Set to the latest HTTP response.

		if req.GetInfo().GetRawHttpResponse() != "" {
			dm.RawHttpResponse = req.GetInfo().GetRawHttpResponse()
		} else {
			slog.Debug("No HTTP response found for URL upload", slog.Int64("request_id", req.RequestId), slog.String("url", req.GetInfo().GetOriginalUrl()), slog.String("honeypot_ip", req.GetInfo().GetHoneypotIp()))
		}

		if err = s.dbClient.Update(&dm); err != nil {
			slog.Warn("could not update", slog.String("error", err.Error()), slog.String("url", req.GetInfo().GetOriginalUrl()))
		}

		// If the existing uploaded file was found malicious then we will generate
		// events for the IPs involved in the current exchange.
		if dm.VTAnalysisMalicious > 0 || dm.VTAnalysisSuspicious > 0 {
			for _, evt := range s.vtMgr.GetEventsForDownload(&dm, false) {
				s.ipEventManager.AddEvent(&evt)
			}
		}

		if s.vtMgr != nil && len(dm.VTURLAnalysisID) == 0 {
			slog.Warn("URL analysis ID is not set!")
			s.vtMgr.QueueURL(dInfo.OriginalUrl)
		}

		s.MaybeExtractLinksFromPayload(req.GetInfo().GetData(), dInfo)
		slog.Debug("Updated existing entry for URL upload", slog.Int64("request_id", req.RequestId), slog.String("url", req.GetInfo().GetOriginalUrl()))
		s.metrics.fileUploadRpcResponseTime.Observe(time.Since(rpcStartTime).Seconds())
		return &backend_service.UploadFileResponse{}, nil
	}

	if err != nil && !errors.Is(err, ksql.ErrRecordNotFound) {
		slog.Warn("unexpected database error", slog.String("error", err.Error()))
		return &backend_service.UploadFileResponse{}, status.Errorf(codes.Internal, "unexpected database error: %s", err)
	}

	s.whoisMgr.LookupIP(req.GetInfo().GetIp())

	targetDir := fmt.Sprintf("%s/%d", s.config.Backend.Downloader.MalwareDownloadDir, req.RequestId)
	if _, err = os.Stat(targetDir); os.IsNotExist(err) {
		// Due to concurrency, it is possible that between the check for whether the
		// directory exists and creating one, the directory is already created.
		// Therefore we double check here that any error during creation is no
		// ErrExist which we'll allow.
		if err = os.Mkdir(targetDir, 0755); err != nil && !os.IsExist(err) {
			return retResponse, status.Errorf(codes.Internal, "creating dir: %s", err)
		}
	}

	targetFile := fmt.Sprintf("%s/%d", targetDir, rand.Intn(100000))
	outFileHandle, err := os.Create(targetFile)
	if err != nil {
		return retResponse, status.Errorf(codes.Internal, "creating file: %s", err)
	}

	defer outFileHandle.Close()

	bytesWritten, err := io.Copy(outFileHandle, bytes.NewReader(req.GetInfo().GetData()))
	if err != nil {
		return retResponse, status.Errorf(codes.Internal, "writing file: %s", err)
	}

	dInfo.Size = bytesWritten
	dInfo.FileLocation = targetFile
	_, err = s.dbClient.Insert(&dInfo)
	if err != nil {
		slog.Warn("error on insert", slog.String("error", err.Error()))
		return &backend_service.UploadFileResponse{}, status.Errorf(codes.Internal, "unexpected database error on insert: %s", err)
	}

	slog.Debug("Added entry for URL upload", slog.Int64("request_id", req.RequestId), slog.String("url", req.GetInfo().GetOriginalUrl()))
	if s.vtMgr != nil {
		slog.Debug("Adding URL to VT queue", slog.Int64("request_id", req.RequestId), slog.String("url", req.GetInfo().GetOriginalUrl()))
		s.vtMgr.QueueURL(dInfo.OriginalUrl)
	}

	s.MaybeExtractLinksFromPayload(req.GetInfo().GetData(), dInfo)

	s.metrics.fileUploadRpcResponseTime.Observe(time.Since(rpcStartTime).Seconds())
	return &backend_service.UploadFileResponse{}, nil
}

func (s *BackendServer) getResponderData(sReq *models.Request, rule *models.ContentRule, content *models.Content) string {
	reg, err := regexp.Compile(rule.ResponderRegex)
	if err == nil && reg != nil && s.llmResponder != nil {
		match := reg.FindSubmatch(sReq.Raw)

		if len(match) < 2 {
			return strings.Replace(string(content.Data), constants.LLMReplacementTag, responder.LLMReplacementFallbackString, 1)
		}

		final_match := ""
		switch rule.ResponderDecoder {
		case constants.ResponderDecoderTypeNone:
			final_match = string(match[1])
		case constants.ResponderDecoderTypeUri:
			final_match = decoding.DecodeURLOrEmptyString(string(match[1]), true)
			if final_match == "" {
				logutil.Error("could not decode URI", sReq, slog.String("match", string(match[1])))
			}
		case constants.ResponderDecoderTypeHtml:
			final_match = decoding.DecodeHTML(string(match[1]))
		default:
			logutil.Error("unknown responder decoder", sReq, slog.String("decoder", rule.ResponderDecoder))
		}

		if final_match == "" {
			return strings.Replace(string(content.Data), constants.LLMReplacementTag, responder.LLMReplacementFallbackString, 1)
		}

		body, err := s.llmResponder.Respond(rule.Responder, final_match, string(content.Data))
		if err != nil {
			logutil.Error("error responding", sReq, slog.String("match", final_match), slog.String("error", err.Error()))
		}
		return body
	}
	// Remove the tag and send the template as-is
	return strings.Replace(string(content.Data), constants.LLMReplacementTag, responder.LLMReplacementFallbackString, 1)
}

func (s *BackendServer) CheckForConsecutivePayloads(sReq *models.Request, preRes *preprocess.PreProcessResult) {

	if preRes.PayloadType != constants.TriagePayloadTypeShellCommand &&
		preRes.PayloadType != constants.TriagePayloadTypeCodeExec &&
		preRes.PayloadType != constants.TriagePayloadTypeSqlInjection {
		return
	}

	cKey := fmt.Sprintf("%d:%s:%s:%s", sReq.SessionID, sReq.BaseHash, preRes.PayloadType, preRes.TargetedParameter)
	pHash := string(util.FastCacheHash(preRes.Payload))

	s.payloadSessionCache.GetOrCreate(cKey,
		func() map[string]string { return make(map[string]string) },
		func(val *map[string]string) {
			// If this payload is not seen before and there are already entries in the
			// masp then we will create an event.
			if _, ok := (*val)[pHash]; !ok {
				if len(*val) > 0 {
					// Parsing of the payload is not always reliable so we will first
					// check to see if there is not an entry with the exact same
					// cmp_hash. If there is one then it means that we got two different
					// cKeys for the exact same request which extremely likely is due to
					// the payload not being parsed out the same in both cases. This is
					// very noisy and we will filter that out here.

					for _, v := range *val {
						if v == sReq.CmpHash {
							logutil.Debug("found duplicate payload cmp_hash in cache!", sReq)
							return
						}
					}

					// Only create event if we've seen at least one other payload before.
					logutil.Debug("found new consecutive payload for session", sReq, slog.String("base_hash", sReq.BaseHash), slog.String("target_param", preRes.TargetedParameter))

					refType2 := constants.IpEventRefTypeParameter
					s.ipEventManager.AddEvent(&models.IpEvent{
						IP:             sReq.SourceIP,
						Type:           constants.IpEventSessionInfo,
						Subtype:        constants.IpEventSubTypeSuccessivePayload,
						Details:        fmt.Sprintf("successive payloads - %s", preRes.PayloadType),
						Source:         constants.IpEventSourceAnalysis,
						SourceRef:      fmt.Sprintf("%d", sReq.SessionID),
						SourceRefType:  constants.IpEventRefTypeSessionId,
						SourceRef2:     &preRes.TargetedParameter,
						SourceRefType2: &refType2,
						RequestID:      sReq.ID,
						HoneypotIP:     sReq.HoneypotIP,
					})
				}
				(*val)[pHash] = sReq.CmpHash
			}
		},
	)
}

func (s *BackendServer) GetPreProcessResponse(sReq *models.Request, filter bool) (*preprocess.PayloadProcessingResult, error) {

	var preRes *preprocess.PreProcessResult
	var err error
	var payloadResponse *preprocess.PayloadProcessingResult

	s.metrics.firstTriageTotal.WithLabelValues("input_count").Inc()

	if filter {
		// Check the cache is the cmp_hash is in there. Remember that this hash is
		// broad and should match all requests that are similar to the original one.
		// This check here is therefore not limited to only the requests coming from
		// the original IP. Instead we want to preprocess all similar requests in the
		// future for the duration of the entry in the cache.
		if _, err = s.payloadCmpHashCache.Get(sReq.CmpHash); err == nil {
			logutil.Debug("found payload cmp_hash in cache!", sReq, slog.String("url", sReq.Uri))
			s.metrics.firstTriageSelection.WithLabelValues("filter_accept_similar").Inc()
			preRes, payloadResponse, err = s.preprocessor.Process(sReq)
		} else {
			// Use MaybeProcess which means that the preprocessing will only happen if
			// the request matches certain characters (e.g. if has /bin/sh in the
			// body).
			preRes, payloadResponse, err = s.preprocessor.MaybeProcess(sReq)
			if err != nil {

				if errors.Is(err, preprocess.ErrNotProcessed) {
					s.metrics.firstTriageSelection.WithLabelValues("filter_reject").Inc()
					return nil, preprocess.ErrNotProcessed
				} else {
					s.metrics.firstTriageSelection.WithLabelValues("preprocess_error").Inc()
					return nil, fmt.Errorf("not preprocess error: %w", err)
				}
			}
			s.metrics.firstTriageSelection.WithLabelValues("filter_accept").Inc()
		}
	} else {
		preRes, payloadResponse, err = s.preprocessor.Process(sReq)
		s.metrics.firstTriageSelection.WithLabelValues("direct_accept").Inc()
	}

	if err != nil {
		s.metrics.firstTriageResult.WithLabelValues("error").Inc()
		return nil, fmt.Errorf("error pre-processing: %s", err)
	}

	if preRes == nil {
		s.metrics.firstTriageResult.WithLabelValues("error_no_response").Inc()
		return nil, fmt.Errorf("no pre-processing response")
	}

	// Mark as triaged only after we have a valid preprocessing result.
	// This ensures Triaged=true only when we have definitive results.
	sReq.Triaged = true

	if !preRes.HasPayload {
		sReq.TriageHasPayload = false
		s.metrics.firstTriageResult.WithLabelValues("success_no_payload").Inc()
		return nil, fmt.Errorf("no payload found")
	}

	if payloadResponse == nil {
		logutil.Error("no payload response", sReq, slog.String("url", sReq.Uri), slog.String("cmp_hash", sReq.CmpHash))
		return nil, fmt.Errorf("no payload response found")
	}
	logutil.Debug("found payload", sReq, slog.String("url", sReq.Uri), slog.String("cmp_hash", sReq.CmpHash), slog.String("type", preRes.PayloadType))

	s.metrics.firstTriageResult.WithLabelValues("success_payload").Inc()
	s.metrics.firstTriagePayloadType.WithLabelValues(preRes.PayloadType).Inc()

	// Update the cache in order to also preprocess future similar requests.
	s.payloadCmpHashCache.Store(sReq.CmpHash, struct{}{})

	s.CheckForConsecutivePayloads(sReq, preRes)

	sReq.TriageHasPayload = true
	sReq.TriagePayload = preRes.Payload
	sReq.TriagePayloadType = preRes.PayloadType
	sReq.RawResponse = payloadResponse.Output
	if preRes.TargetedParameter != "" {
		sReq.TriageTargetParameter = &preRes.TargetedParameter
	}

	logArgs := []any{
		slog.String("cmp_hash", sReq.CmpHash),
		slog.Bool("triaged", sReq.Triaged),
		slog.Bool("triage_has_payload", sReq.TriageHasPayload),
		slog.String("triage_payload_type", sReq.TriagePayloadType),
		slog.Int("raw_response_len", len(sReq.RawResponse)),
	}
	if sReq.TriageTargetParameter != nil {
		logArgs = append(logArgs, slog.String("triage_target_parameter", *sReq.TriageTargetParameter))
	}
	logutil.Debug("updating triaged request", sReq, logArgs...)
	return payloadResponse, nil
}

func (s *BackendServer) handlePreProcess(sReq *models.Request, content *models.Content, res *backend_service.HttpResponse, finalHeaders *map[string]string, rpcStartTime time.Time, filter bool) error {
	payloadResponse, err := s.GetPreProcessResponse(sReq, filter)

	if err != nil {
		if !errors.Is(err, preprocess.ErrNotProcessed) {
			return fmt.Errorf("error pre-processing: %w", err)
		}
		return nil
	}

	if payloadResponse.SqlDelayMs > 0 {
		logutil.Debug("sql delay", sReq, slog.Int("ms", payloadResponse.SqlDelayMs))
		rpcDuration := time.Since(rpcStartTime).Milliseconds()
		timeRemainMs := payloadResponse.SqlDelayMs - int(rpcDuration)

		if timeRemainMs <= 0 {
			logutil.Debug("skipping sql delay", sReq, slog.Int("timeRemainMs", timeRemainMs))
		} else {
			logutil.Debug("sql delay", sReq, slog.Int("timeRemainMs", timeRemainMs))
			if timeRemainMs < maxSqlDelayMs {
				time.Sleep(time.Duration(timeRemainMs) * time.Millisecond)
			} else {
				logutil.Error("sql delay too large", sReq, slog.Int("timeRemainMs", timeRemainMs))
			}
		}
	}

	if payloadResponse.TmpContentRule != nil {
		cnt := s.uploadsIPCounts.GetOrCreate(sReq.SourceIP, func() int64 { return 0 }, func(v *int64) { *v++ })
		if cnt > int64(s.config.Backend.Advanced.MaxUploadsPerIP) {
			return fmt.Errorf("IP upload limit reached")
		}

		expiryTime := time.Now().Add(time.Hour * 1)
		payloadResponse.TmpContentRule.Content.ValidUntil = &expiryTime
		payloadResponse.TmpContentRule.Rule.ValidUntil = &expiryTime

		pLen := len(payloadResponse.TmpContentRule.Content.Data)
		if pLen > s.config.Backend.Advanced.MaxUploadSizeBytes {
			return fmt.Errorf("rejecting payload upload: too long (%d bytes)", pLen)
		}

		insertedContent, err := s.dbClient.Insert(&payloadResponse.TmpContentRule.Content)
		if err != nil {
			return fmt.Errorf("error inserting tmp content: %w", err)
		}

		payloadResponse.TmpContentRule.Rule.ContentID = insertedContent.ModelID()
		rule, err := s.dbClient.Insert(&payloadResponse.TmpContentRule.Rule)
		if err != nil {
			return fmt.Errorf("error inserting tmp rule: %w", err)
		}

		hp, err := s.getCachedHoneypot(sReq.HoneypotIP)
		if err != nil {
			return fmt.Errorf("error finding honeypot. IP: %s, Err: %w", sReq.HoneypotIP, err)
		}

		if _, err := s.dbClient.Insert(&models.RulePerGroup{RuleID: rule.ModelID(), GroupID: hp.RuleGroupID}); err != nil {
			return fmt.Errorf("error inserting rule per group: %w", err)
		}

		slog.Debug("Added tmp rule", slog.Int64("request_id", sReq.ID), slog.Int64("session_id", sReq.SessionID), slog.String("network", *payloadResponse.TmpContentRule.Rule.AllowFromNet), slog.Int64("rule_id", rule.ModelID()), slog.String("rule_uri", payloadResponse.TmpContentRule.Rule.Uri))

		newRule := rule.(*models.ContentRule)
		s.safeRules.Add(*newRule, constants.DefaultRuleGroupID)
	}

	res.Body = []byte(AddLLMResponseToContent(content, payloadResponse.Output))
	if payloadResponse.Headers != "" {
		util.ParseHeaders(payloadResponse.Headers, finalHeaders)
	}

	return nil
}

// HandleProbe receives requests from te honeypots and tells them how to
// respond.
func (s *BackendServer) HandleProbe(ctx context.Context, req *backend_service.HandleProbeRequest) (*backend_service.HandleProbeResponse, error) {

	_, ok := auth.GetHoneypotMetadata(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authentication found")
	}
	slog.Info("Got request", slog.String("uri", req.GetRequestUri()), slog.String("method", req.GetRequest().GetMethod()), slog.String("ip", req.GetRequest().GetRemoteAddress()))

	rpcStartTime := time.Now()
	sReq, err := s.ProbeRequestToDatabaseRequest(req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot convert request: %s", err)
	}

	session, err := s.sessionMgr.GetCachedSession(sReq.SourceIP)
	if err != nil || session == nil {
		session, err = s.sessionMgr.StartSession(sReq.SourceIP)
		if err != nil {
			logutil.Error("error starting session", sReq, slog.String("error", err.Error()))
		} else {
			session.LastRuleServed.AppID = -1
		}
	}
	sReq.SessionID = session.ID

	for _, limiter := range s.rateLimiters {
		allowRequest, err := limiter.AllowRequest(sReq)
		if !allowRequest {
			evt := &models.IpEvent{
				IP:            sReq.SourceIP,
				Type:          constants.IpEventRateLimited,
				Details:       err.Error(),
				Source:        constants.IpEventSourceBackend,
				SourceRef:     fmt.Sprintf("%d", session.ID),
				SourceRefType: constants.IpEventRefTypeSessionId,
				HoneypotIP:    sReq.HoneypotIP,
			}

			switch err {
			case ratelimit.ErrSessionIPBucketLimitExceeded:
				evt.Subtype = constants.IpEventSubTypeRateSessionIPBucket
			case ratelimit.ErrSessionIPWindowLimitExceeded:
				evt.Subtype = constants.IpEventSubTypeRateSessionIPWindow
			case ratelimit.ErrSourceIPBucketLimitExceeded:
				evt.Subtype = constants.IpEventSubTypeRateSourceIPBucket
			case ratelimit.ErrSourceIPWindowLimitExceeded:
				evt.Subtype = constants.IpEventSubTypeRateSourceIPWindow
			case ratelimit.ErrURIBucketLimitExceeded:
				evt.Subtype = constants.IpEventSubTypeRateURIBucket
			case ratelimit.ErrURIWindowLimitExceeded:
				evt.Subtype = constants.IpEventSubTypeRateURIWindow

			default:
				// Try to map based on limiter name if the error isn't one of the standard ones,
				// or just log it. For now, we'll keep the default logging but maybe add metrics?
				// The prompt asked to keep same metrics but simplify if possible.
				// If we use standard errors for the new limiters, the switch works.
				logutil.Error("error happened in ratelimiter", sReq, slog.String("error", err.Error()), slog.String("limiter", limiter.Name()))
			}

			s.ipEventManager.AddEvent(evt)

			logutil.Debug("ratelimiter blocked request", sReq, slog.String("error", err.Error()), slog.String("limiter", limiter.Name()))
			return nil, status.Errorf(codes.ResourceExhausted, "ratelimiter blocked request: %s", err)
		}
	}

	s.metrics.requestsPerPort.WithLabelValues(fmt.Sprintf("%d", sReq.Port)).Add(1)
	s.metrics.methodPerRequest.WithLabelValues(sReq.Method).Add(1)
	s.metrics.honeypotRequests.WithLabelValues(sReq.HoneypotIP).Add(1)
	s.metrics.reqsQueueGauge.Set(float64(len(s.reqsQueue)))

	hp, hpErr := s.getCachedHoneypot(sReq.HoneypotIP)
	if hpErr != nil {
		logutil.Error("error finding honeypot", sReq, slog.String("error", hpErr.Error()), slog.String("honeypot", sReq.HoneypotIP))
		return nil, status.Errorf(codes.Internal, "honeypot error: %s", hpErr.Error())
	}

	matchedRule, ruleErr := GetMatchedRule(s.safeRules.GetGroup(hp.RuleGroupID), sReq, session)
	matchedRuleIsDefault := false

	if ruleErr != nil {
		// If there was no matched rule then serve the default content of the honeypot.
		matchedRuleIsDefault = true
		matchedRule.ContentID = hp.DefaultContentID
		matchedRule.AppID = 0
		matchedRule.ID = 0
	}

	// Already update the cached session immediately so that consecutive requests
	// can take into account session info such as the last matched rule.
	s.UpdateSessionWithRule(sReq.SourceIP, session, &matchedRule)

	// Also do another update at the end of the RPC to capture time the last
	// request of the session was served.
	defer func() {
		if session.RequestCount > 0 {
			timeDiff := rpcStartTime.Sub(session.LastRequestAt)
			session.AddRequestGap(timeDiff.Seconds())
		}

		// We use time.Now instead of rpcStartTime because we really want to capture
		// the time the RPC is finished and not when it started.
		session.SetLastRequestAt(time.Now())
		session.IncreaseRequestCount()
		s.UpdateSessionWithRule(sReq.SourceIP, session, &matchedRule)
	}()

	// Alert if necessary
	if matchedRule.Alert {
		if s.config.Alerting.WebInterfaceAddress != "" {
			s.alertMgr.SendBufferedMessage(fmt.Sprintf("Rule ID: %d\nURI: %s\nLink: %s/requests?q=session_id:%d", matchedRule.ID, sReq.Uri, s.config.Alerting.WebInterfaceAddress, sReq.SessionID))
		} else {
			s.alertMgr.SendBufferedMessage(fmt.Sprintf("Rule ID: %d\nURI: %s", matchedRule.ID, sReq.Uri))
		}
	}

	if matchedRule.Block {
		s.metrics.requestsBlocked.Inc()
		return nil, status.Errorf(codes.PermissionDenied, "Rule blocks request")
	}

	sReq.ContentID = matchedRule.ContentID
	sReq.RuleID = matchedRule.ID
	sReq.AppID = matchedRule.AppID
	sReq.RuleUuid = matchedRule.ExtUuid
	sReq.CreatedAt = time.Now().UTC()

	dm, err := s.dbClient.Insert(sReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not save request to database: %s", err)
	}
	sReq = dm.(*models.Request)

	if len(matchedRule.TagsToApply) > 0 {
		for _, tagperrule := range matchedRule.TagsToApply {
			go func() {
				if _, err := s.dbClient.Insert(&models.TagPerRequest{TagID: tagperrule.TagID, RequestID: sReq.ID, TagPerRuleID: &tagperrule.ID}); err != nil {
					logutil.Error("error inserting tag", sReq, slog.Int64("tag_per_rule_id", tagperrule.TagID), slog.String("error", err.Error()))
				}
			}()
		}
	}

	// If a dynamic rule was requested, create an event.
	if matchedRule.ValidUntil != nil && matchedRule.AllowFromNet != nil {
		s.ipEventManager.AddEvent(&models.IpEvent{
			IP:            sReq.SourceIP,
			Type:          constants.IpEventRule,
			Subtype:       constants.IpEventSubTypeDynamicRule,
			Details:       "dynamic rule was requested",
			Source:        constants.IpEventSourceRule,
			SourceRef:     fmt.Sprintf("%d", matchedRule.ID),
			SourceRefType: constants.IpEventRefTypeRuleId,
			RequestID:     sReq.ID,
			HoneypotIP:    sReq.HoneypotIP,
		})
	}

	colEx := extractors.NewExtractorCollection(true)
	colEx.ParseRequest(sReq)

	// Defer adding it to the requests queue. We always want it added, even on
	// failure but we want to add it as late as possible because some additional
	// data can be added to the request in the logic below.
	defer func() {
		s.reqsQueue <- ReqQueueEntry{
			req:        sReq,
			rule:       matchedRule,
			eCollector: colEx,
		}
	}()

	logutil.Debug("Fetching content", sReq, slog.Int64("content_id", matchedRule.ContentID))
	content, err := s.dbClient.GetContentByID(matchedRule.ContentID)
	if err != nil {
		logutil.Error("error getting content", sReq, slog.String("honeypot", sReq.HoneypotIP), slog.Int64("content_id", matchedRule.ContentID), slog.String("error", err.Error()))
		return nil, status.Errorf(codes.Unavailable, "fetching content ID %d: %s", matchedRule.ContentID, err)
	}

	res := &backend_service.HttpResponse{}
	res.StatusCode = content.StatusCode

	// Prepare the final headers for the request. These can still be subject to
	// change due to the script response, the LLM response or the Content headers.
	finalHeaders := make(map[string]string)
	finalHeaders["Content-Type"] = content.ContentType
	finalHeaders["Server"] = content.Server

	// Add debug headers for requests from debug IPs.
	if s.isDebugIP(sReq.SourceIP) {
		finalHeaders[DebugHeaderRequestID] = fmt.Sprintf("%d", sReq.ID)
		finalHeaders[DebugHeaderSessionID] = fmt.Sprintf("%d", sReq.SessionID)
	}

	if content.Script != "" {
		logutil.Debug("running script", sReq)
		err := s.jRunner.RunScript(content.Script, *sReq, res, colEx, false)
		if err != nil {
			logutil.Warn("couldn't run script", sReq, slog.String("error", err.Error()))
		} else {
			sReq.ContentDynamic = true
			if len(res.GetHeader()) > 0 {
				for _, h := range res.GetHeader() {
					sReq.RawResponse = fmt.Sprintf("%s\n%s: %s", sReq.RawResponse, h.GetKey(), h.GetValue())
				}

				sReq.RawResponse = fmt.Sprintf("%s\n\n%s", sReq.RawResponse, string(res.Body))
			} else {
				sReq.RawResponse = string(res.Body)
			}
		}

	} else {

		if matchedRule.Responder != "" && matchedRule.Responder != constants.ResponderTypeNone {
			if matchedRule.Responder == constants.ResponderTypeAuto {
				err := s.handlePreProcess(sReq, &content, res, &finalHeaders, rpcStartTime, false)
				if err != nil {
					slog.Error("error handling pre-process", slog.Int64("request_id", sReq.ID), slog.Int64("session_id", sReq.SessionID), slog.String("error", err.Error()))
					if content.HasCode {
						// We wouldn't want to return the code itself.
						res.Body = []byte(FallbackContent)
					} else {
						res.Body = content.Data
					}
				}
			} else {
				res.Body = []byte(s.getResponderData(sReq, &matchedRule, &content))
				sReq.RawResponse = string(res.Body)
			}
		} else {
			if content.HasCode && s.codeInterpreter != nil {
				llmRes, err := s.codeInterpreter.Interpret(sReq, &content)
				if err != nil {

					logutil.Error("error interpreting code", sReq, slog.String("error", err.Error()))
					return nil, status.Errorf(codes.Internal, "running content code: %s", err.Error())
				}

				logutil.Debug("got llm response", sReq, slog.Int64("content_id", matchedRule.ContentID), slog.String("llm_response", string(llmRes.Stdout)))
				res.Body = llmRes.Stdout
				sReq.RawResponse = string(llmRes.Stdout)

				if len(llmRes.Headers) > 0 {
					newHeaders := strings.Split(llmRes.Headers, "\n")
					content.Headers = append(content.Headers, newHeaders...)
				}

			} else {
				res.Body = content.Data
			}
		}
	}

	if matchedRuleIsDefault {
		err := s.handlePreProcess(sReq, &content, res, &finalHeaders, rpcStartTime, true)
		if err != nil {
			slog.Error("error handling pre-process", slog.Int64("request_id", sReq.ID), slog.Int64("session_id", sReq.SessionID), slog.String("error", err.Error()))
			if content.HasCode {
				// We wouldn't want to return the code itself.
				res.Body = []byte(FallbackContent)
			} else {
				res.Body = content.Data
			}
		}
	}

	// Apply the templating and render the macros after the scripts have run. This
	// allows scripts to also output macros.
	templr := templator.NewTemplator()
	if templr == nil {
		logutil.Error("templator is not initialized", sReq)
	} else {
		newBody, err := templr.RenderTemplate(sReq, res.Body)
		if err != nil {
			logutil.Error("error rendering template", sReq, slog.String("error", err.Error()))
		} else {
			res.Body = newBody
		}
	}

	// Add the content headers to the final header list.
	for _, header := range content.Headers {
		util.ParseHeaders(header, &finalHeaders)
	}

	// Render any template values in the headers.
	for key, value := range finalHeaders {
		newHdr, err := templr.RenderTemplate(sReq, []byte(value))
		if err != nil {
			logutil.Error("error rendering template for header", sReq, slog.String("error", err.Error()), slog.String("header", key))
		} else {
			value = string(newHdr)
		}

		res.Header = append(res.Header, &backend_service.KeyValue{
			Key:   key,
			Value: value,
		})
	}

	s.metrics.rpcResponseTime.Observe(time.Since(rpcStartTime).Seconds())

	return &backend_service.HandleProbeResponse{
		Response: res,
	}, nil
}

// LoadRules loads the content rules from the database. It first fetches the
// app-per-group mappings and then fetches the rules for each app separately.
func (s *BackendServer) LoadRules() error {
	appPerGroup, err := s.dbClient.GetAppPerGroupJoin()
	if err != nil {
		return fmt.Errorf("getting app per group: %w", err)
	}

	// Build a map of app ID to the group IDs it belongs to, and track which
	// apps we need to fetch rules for.
	appToGroups := map[int64][]int64{}
	for _, apg := range appPerGroup {
		appToGroups[apg.App.ID] = append(appToGroups[apg.App.ID], apg.AppPerGroup.GroupID)
	}

	ruleCount := 0
	finalRules := map[int64][]models.ContentRule{}
	for appID, groupIDs := range appToGroups {
		rules, err := s.dbClient.SearchContentRules(0, 0, fmt.Sprintf("app_id:%d", appID))
		if err != nil {
			return fmt.Errorf("searching rules for app %d: %w", appID, err)
		}

		for _, rule := range rules {
			if !rule.Enabled {
				slog.Debug("rule disabled", slog.Int64("rule_id", rule.ID), slog.Int64("app_id", rule.AppID))
				continue
			}
			for _, groupID := range groupIDs {
				finalRules[groupID] = append(finalRules[groupID], rule)
				ruleCount++
			}
		}
	}

	slog.Info("loaded rules", slog.Int("rules_count", ruleCount), slog.Int("amount_of_groups", len(finalRules)))
	s.safeRules.Set(finalRules)
	return nil
}

func (s *BackendServer) ProcessReqsQueue() {
	for {
		select {
		case entry := <-s.reqsQueue:
			// TODO: consider doing the next line in a goroutine. Doing so might need
			// some of the logic in ProcessRequest to change. For example, the whois
			// lookup will be inefficient when quickly called for the requests from
			// the same IP.
			startTime := time.Now()
			if err := s.ProcessRequest(entry.req, entry.rule, entry.eCollector); err != nil {
				slog.Warn("process request queue error", slog.String("error", err.Error()))
			}
			s.metrics.reqsQueueResponseTime.Observe(time.Since(startTime).Seconds())

		case <-s.reqsProcessChan:
			slog.Info("Process request queue done")
			return
		}
	}

}

func (s *BackendServer) ProcessRequest(req *models.Request, rule models.ContentRule, eCollector *extractors.ExtractorCollection) error {

	s.whoisMgr.LookupIP(req.SourceIP)

	// Log triage state before database update to help debug potential race conditions
	if req.Triaged {
		logArgs := []any{
			slog.String("cmp_hash", req.CmpHash),
			slog.Bool("triaged", req.Triaged),
			slog.Bool("triage_has_payload", req.TriageHasPayload),
			slog.String("triage_payload_type", req.TriagePayloadType),
			slog.Int("raw_response_len", len(req.RawResponse)),
		}
		if req.TriageTargetParameter != nil {
			logArgs = append(logArgs, slog.String("triage_target_parameter", *req.TriageTargetParameter))
		}
		logutil.Debug("updating triaged request", req, logArgs...)
	}

	err := s.dbClient.Update(req)
	if err != nil {
		return fmt.Errorf("error updating request: %s", err)
	}

	if s.describer != nil {
		err := s.describer.MaybeAddNewHash(req.CmpHash, req)
		if err != nil {
			logutil.Error("error adding new hash", req, slog.String("error", err.Error()))
		}
	}

	if rule.RequestPurpose != models.RuleRequestPurposeUnknown {
		switch rule.RequestPurpose {
		case models.RuleRequestPurposeAttack:
			s.ipEventManager.AddEvent(&models.IpEvent{
				IP:            req.SourceIP,
				Type:          constants.IpEventTrafficClass,
				Subtype:       constants.IpEventSubTypeTrafficClassAttacked,
				Details:       "rule indicated the IP attacked",
				Source:        constants.IpEventSourceRule,
				SourceRef:     fmt.Sprintf("%d", rule.ID),
				SourceRefType: constants.IpEventRefTypeRuleId,
				RequestID:     req.ID,
				HoneypotIP:    req.HoneypotIP,
			})
		case models.RuleRequestPurposeCrawl:
			s.ipEventManager.AddEvent(&models.IpEvent{
				IP:            req.SourceIP,
				Type:          constants.IpEventTrafficClass,
				Subtype:       constants.IpEventSubTypeTrafficClassCrawl,
				Source:        constants.IpEventSourceRule,
				SourceRef:     fmt.Sprintf("%d", rule.ID),
				SourceRefType: constants.IpEventRefTypeRuleId,
				Details:       "rule indicated the IP crawled",
				RequestID:     req.ID,
				HoneypotIP:    req.HoneypotIP,
			})
		case models.RuleRequestPurposeRecon:
			s.ipEventManager.AddEvent(&models.IpEvent{
				IP:            req.SourceIP,
				Source:        constants.IpEventSourceRule,
				SourceRef:     fmt.Sprintf("%d", rule.ID),
				Type:          constants.IpEventTrafficClass,
				Subtype:       constants.IpEventSubTypeTrafficClassRecon,
				SourceRefType: constants.IpEventRefTypeRuleId,
				Details:       "rule indicated the IP reconned",
				RequestID:     req.ID,
				HoneypotIP:    req.HoneypotIP,
			})
		}
	}

	downloadsScheduled := 0
	pingsScheduled := 0

	eCollector.IterateMetadata(req.ID, func(m *models.RequestMetadata) error {

		switch m.Type {
		case constants.ExtractorTypeLink:
			if downloadsScheduled <= maxUrlsToExtractForDownload {
				ipBasedUrl, ip, hostHeader, err := ConvertURLToIPBased(m.Data)
				if err != nil {
					logutil.Warn("error converting URL", req, slog.String("url", m.Data), slog.String("error", err.Error()))
				} else {
					s.ScheduleDownloadOfPayload(req.SourceIP, req.HoneypotIP, m.Data, ip, ipBasedUrl, hostHeader, req.ID)
					downloadsScheduled += 1
				}
			} else {
				logutil.Warn("skipping download due to excessive links", req, slog.String("url", m.Data))
			}

		case constants.ExtractorTypePing:

			if pingsScheduled <= maxPingsToExtract {
				parts := strings.Split(m.Data, " ")
				if len(parts) != 2 {
					logutil.Error("invalid ping request", req, slog.String("data", m.Data))
				} else {
					cnt, err := strconv.Atoi(parts[1])
					if err != nil {
						logutil.Error("invalid ping count", req, slog.String("data", m.Data))
						cnt = 3
					}
					s.SchedulePingOfAddress(req.HoneypotIP, parts[0], int64(cnt), m.RequestID)
				}

			} else {
				logutil.Warn("skipping ping due to excessive amount", req, slog.String("ping", m.Data))
			}
		}

		_, err := s.dbClient.Insert(m)
		if err != nil {
			logutil.Warn("Could not save metadata for request", req, slog.String("error", err.Error()))
		}
		return nil
	})

	return nil
}

func (s *BackendServer) Start() error {
	// Load the rules once.
	err := s.LoadRules()
	if err != nil {
		return fmt.Errorf("loading rules: %s", err)
	}

	s.alertMgr.Start()
	go s.ProcessReqsQueue()

	// Setup the rules reloading.
	maintenanceTicker := time.NewTicker(s.config.Backend.Advanced.MaintenanceRoutineInterval)
	go func() {
		for {
			select {
			case <-s.maintenanceChan:
				maintenanceTicker.Stop()
				return
			case <-maintenanceTicker.C:

				s.sessionCache.CleanExpired()
				s.downloadsCache.CleanExpired()
				s.pingsCache.CleanExpired()

				// Reload the rules.
				cl := len(s.safeRules.Get())
				if err = s.LoadRules(); err != nil {
					slog.Error("reloading rules", slog.String("error", err.Error()))
				}
				nl := len(s.safeRules.Get())

				if cl != nl {
					slog.Info("Rules updated\n", slog.Int("from", cl), slog.Int("to", nl))
				}
			}
		}
	}()

	qRunnerTicker := time.NewTicker(s.config.Backend.Advanced.QueriesRunnerInterval)
	go func() {
		for {
			select {
			case <-s.qRunnerChan:
				qRunnerTicker.Stop()
				return
			case <-qRunnerTicker.C:
				start := time.Now()
				if err := s.qRunner.Run(time.Duration(-2) * s.config.Backend.Advanced.QueriesRunnerInterval); err != nil {
					slog.Warn("error running queries", slog.String("error", err.Error()))
				}
				s.metrics.qRunnerResponseTime.Observe(time.Since(start).Seconds())
			}
		}
	}()

	return nil
}

func (s *BackendServer) Stop() {
	// Stop the rules loading.
	s.maintenanceChan <- true
	s.reqsProcessChan <- true
	s.qRunnerChan <- true
	s.dbClient.Close()
	s.alertMgr.Stop()
}
