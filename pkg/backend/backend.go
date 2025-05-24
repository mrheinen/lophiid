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
	"lophiid/pkg/triage/describer"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"lophiid/pkg/util/decoding"
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
	pingQueue           map[string][]backend_service.CommandPingAddress
	pingQueueMu         sync.Mutex
	pingsCache          *util.StringMapCache[time.Time]
	metrics             *BackendMetrics
	rateLimiter         ratelimit.RateLimiter
	ipEventManager      analysis.IpEventManager
	config              Config
	llmResponder        responder.Responder
	sessionMgr          session.SessionManager
	describer           describer.DescriberClient
	hCache              *util.StringMapCache[models.Honeypot]
}

// NewBackendServer creates a new instance of the backend server.
func NewBackendServer(c database.DatabaseClient, metrics *BackendMetrics, jRunner javascript.JavascriptRunner, alertMgr *alerting.AlertManager, vtManager vt.VTManager, wManager whois.RdapManager, qRunner QueryRunner, rateLimiter ratelimit.RateLimiter, ipEventManager analysis.IpEventManager, llmResponder responder.Responder, sessionMgr session.SessionManager, describer describer.DescriberClient, config Config) *BackendServer {

	sCache := util.NewStringMapCache[models.ContentRule]("content_cache", config.Backend.Advanced.ContentCacheDuration)
	// Setup the download cache and keep entries for 5 minutes. This means that if
	// we get a request with the same download (payload URL) within that time
	// window then we will not download it again.
	dCache := util.NewStringMapCache[time.Time]("download_cache", config.Backend.Advanced.DownloadCacheDuration)
	// Set up the counters for downloads per IP. This is a very basic way of
	// limiting the amount of downloads an IP can make per 5 minutes.
	dIPCount := util.NewStringMapCache[int64]("download_ip_counters", time.Minute*5)
	dIPCount.Start()

	// Same for the ping cache.
	pCache := util.NewStringMapCache[time.Time]("ping_cache", config.Backend.Advanced.PingCacheDuration)

	// The honeypot cache is simply to try and reduce the amount of honeypot
	// queries to the database.
	hCache := util.NewStringMapCache[models.Honeypot]("honeypot_cache", time.Minute*15)
	hCache.Start()

	return &BackendServer{
		dbClient:            c,
		jRunner:             jRunner,
		qRunner:             qRunner,
		qRunnerChan:         make(chan bool),
		alertMgr:            alertMgr,
		vtMgr:               vtManager,
		whoisMgr:            wManager,
		safeRules:           &SafeRules{},
		maintenanceChan:     make(chan bool),
		reqsProcessChan:     make(chan bool),
		reqsQueue:           make(chan ReqQueueEntry, config.Backend.Advanced.RequestsQueueSize),
		downloadQueue:       make(map[string][]backend_service.CommandDownloadFile),
		downloadsCache:      dCache,
		downloadsIPCounts:   dIPCount,
		downloadsIPCountsMu: sync.Mutex{},
		pingQueue:           make(map[string][]backend_service.CommandPingAddress),
		pingsCache:          pCache,
		sessionCache:        sCache,
		metrics:             metrics,
		config:              config,
		rateLimiter:         rateLimiter,
		ipEventManager:      ipEventManager,
		llmResponder:        llmResponder,
		sessionMgr:          sessionMgr,
		describer:           describer,
		hCache:              hCache,
	}
}

func (s *BackendServer) ScheduleDownloadOfPayload(sourceIP string, honeypotIP string, originalUrl string, targetIP string, targetUrl string, hostHeader string, requestID int64) bool {
	_, err := s.downloadsCache.Get(originalUrl)
	if err == nil {
		slog.Debug("skipping download as it is in the cache", slog.String("url", originalUrl))
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
			slog.Debug("skipping download as IP is over the limit", slog.String("url", originalUrl), slog.String("ip", sourceIP))
			return false
		}
	}

	slog.Debug("adding URL to cache", slog.String("original_url", originalUrl))
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
		slog.Debug("skipping ping as it is in the cache", slog.String("address", address))
		return false
	}

	slog.Debug("adding ping address to cache", slog.String("address", address))
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

	return &sReq, nil
}
func MatchesString(method string, dataToSearch string, searchValue string) bool {
	if searchValue == "" {
		return false
	}

	switch method {
	case "exact":
		return dataToSearch == searchValue
	case "prefix":
		return strings.HasPrefix(dataToSearch, searchValue)
	case "suffix":
		return strings.HasSuffix(dataToSearch, searchValue)
	case "contains":
		return strings.Contains(dataToSearch, searchValue)
	case "regex":
		matched, err := regexp.MatchString(searchValue, dataToSearch)
		// Most cases should be catched when validating a contentrule upon
		// creation.
		if err != nil {
			slog.Warn("Invalid regex", slog.String("error", err.Error()))
			return false
		}
		return matched
	default:
		return false
	}
}

func (s *BackendServer) GetMatchedRule(rules []models.ContentRule, req *models.Request, session *models.Session) (models.ContentRule, error) {
	var matchedRules []models.ContentRule
	for _, rule := range rules {

		if len(rule.Ports) != 0 {
			found := false
			for _, port := range rule.Ports {
				if int64(port) == req.Port {
					found = true
					break
				}
			}

			// This means ports were specified but none matched the request. In that
			// case we can continue the search.
			if !found {
				continue
			}
		}

		if rule.Method != "ANY" && rule.Method != req.Method {
			continue
		}

		matchedUri := MatchesString(rule.UriMatching, req.Uri, rule.Uri)
		matchedBody := MatchesString(rule.BodyMatching, string(req.Body), rule.Body)

		// We assume here that at least path or body are set.
		matched := false
		if matchedUri && rule.Body == "" {
			matched = true
		} else if matchedBody && rule.Uri == "" {
			matched = true
		} else if matchedBody && matchedUri {
			matched = true
		}

		if matched {
			matchedRules = append(matchedRules, rule)
		}
	}

	if len(matchedRules) == 0 {
		return models.ContentRule{}, fmt.Errorf("no rule found")
	}

	if len(matchedRules) == 1 {
		s.UpdateSessionWithRule(req.SourceIP, session, &matchedRules[0])
		return matchedRules[0], nil
	}

	var unservedRules []models.ContentRule
	// Find out what rules match but haven't been served.
	for _, r := range matchedRules {

		if !session.HasServedRule(r.ID) {
			unservedRules = append(unservedRules, r)

			// A rule matching the same app id is prefered.
			if r.AppID == session.LastRuleServed.AppID {
				s.UpdateSessionWithRule(req.SourceIP, session, &r)
				return r, nil
			}
		}
	}

	var matchedRule models.ContentRule
	if len(unservedRules) > 0 {
		// Rules with ports get priority.
		foundPortRule := false
		for _, rule := range unservedRules {
			if len(rule.Ports) > 0 {
				foundPortRule = true
				matchedRule = rule
				break
			}
		}

		if !foundPortRule {
			matchedRule = unservedRules[rand.Int()%len(unservedRules)]
		}

	} else {
		// In this case all rule content combinations have been served at least
		// once to this target. We send a random one.
		matchedRule = matchedRules[rand.Int()%len(matchedRules)]
	}

	s.UpdateSessionWithRule(req.SourceIP, session, &matchedRule)
	return matchedRule, nil
}

func (s *BackendServer) UpdateSessionWithRule(ip string, session *models.Session, rule *models.ContentRule) {
	session.LastRuleServed = *rule
	session.ServedRuleWithContent(rule.ID, rule.ContentID)
	if err := s.sessionMgr.UpdateCachedSession(ip, session); err != nil {
		slog.Error("error updating session", slog.String("ip", ip), slog.String("error", err.Error()))
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

	slog.Info("ping status", slog.String("ip", req.GetAddress()), slog.String("outcome", outcome), slog.Int64("packets_sent", req.GetPacketsSent()), slog.Int64("packets_received", req.GetPacketsReceived()), slog.Int64("average_rtt", req.GetAverageRttMs()), slog.Int64("min_rtt", req.GetMinRttMs()), slog.Int64("max_rtt", req.GetMaxRttMs()))
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
			IP:          req.GetIp(),
			Version:     req.GetVersion(),
			LastCheckin: time.Now(),
		}

		hp.Ports = append(hp.Ports, req.GetListenPort()...)
		hp.SSLPorts = append(hp.Ports, req.GetListenPortSsl()...)

		_, err := s.dbClient.Insert(hp)

		if err != nil {
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

func HasParseableContent(fileUrl string, mime string) bool {
	consumableContentTypes := map[string]bool{
		"application/x-shellscript": true,
		"application/x-sh":          true,
		"application/x-perl":        true,
		"text/x-shellscript":        true,
		"text/x-sh":                 true,
		"text/x-perl":               true,
		"text/plain":                true,
	}

	parsedUrl, err := url.Parse(fileUrl)
	if err != nil {
		slog.Warn("could not parse URL", slog.String("url", fileUrl))
		return false
	}

	contentParts := strings.Split(mime, ";")
	_, hasGoodContent := consumableContentTypes[contentParts[0]]
	return hasGoodContent || strings.HasSuffix(parsedUrl.Path, ".sh") ||
		strings.HasSuffix(parsedUrl.Path, ".pl") ||
		strings.HasSuffix(parsedUrl.Path, ".bat") ||
		strings.HasSuffix(parsedUrl.Path, ".rb") ||
		strings.HasSuffix(parsedUrl.Path, ".py")
}

// getCachedHoneypot returns the honeypot with the given IP from the cache.
func (s *BackendServer) getCachedHoneypot(hpIP string) (*models.Honeypot, error) {
	// Check the cache.
	hp, err := s.hCache.Get(hpIP)
	if err != nil {
		// Not in cache so fetch from the database
		hps, err := s.dbClient.SearchHoneypots(0, 1, fmt.Sprintf("ip:%s", hpIP))
		if err != nil {
			return nil, fmt.Errorf("error finding honeypot: %w", err)
		}

		if len(hps) == 1 {
			// Update the cache.
			s.hCache.Store(hpIP, hps[0])
			hp = &hps[0]
		} else {
			slog.Error("could not find honeypot", slog.String("ip", hpIP))
			return nil, nil
		}
	}
	return hp, nil
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
			slog.Debug("No HTTP response found for URL upload", slog.String("url", req.GetInfo().GetOriginalUrl()), slog.String("honeypot_ip", req.GetInfo().GetHoneypotIp()))
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
		slog.Debug("Updated existing entry for URL upload", slog.String("url", req.GetInfo().GetOriginalUrl()))
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

	slog.Debug("Added entry for URL upload", slog.String("url", req.GetInfo().GetOriginalUrl()))
	if s.vtMgr != nil {
		slog.Debug("Adding URL to VT queue", slog.String("url", req.GetInfo().GetOriginalUrl()))
		s.vtMgr.QueueURL(dInfo.OriginalUrl)
	}

	s.MaybeExtractLinksFromPayload(req.GetInfo().GetData(), dInfo)

	s.metrics.fileUploadRpcResponseTime.Observe(time.Since(rpcStartTime).Seconds())
	return &backend_service.UploadFileResponse{}, nil
}

func (s *BackendServer) getResponderData(sReq *models.Request, rule *models.ContentRule, content *models.Content) string {
	reg, err := regexp.Compile(rule.ResponderRegex)
	if err == nil && reg != nil && s.llmResponder != nil {
		match := reg.FindStringSubmatch(sReq.Raw)

		if len(match) < 2 {
			return strings.Replace(string(content.Data), responder.LLMReplacementTag, responder.LLMReplacementFallbackString, 1)
		}

		final_match := ""
		switch rule.ResponderDecoder {
		case constants.ResponderDecoderTypeNone:
			final_match = match[1]
		case constants.ResponderDecoderTypeUri:
			final_match = decoding.DecodeURLOrEmptyString(match[1], true)
			if final_match == "" {
				slog.Error("could not decode URI", slog.String("match", match[1]))
			}
		case constants.ResponderDecoderTypeHtml:
			final_match = decoding.DecodeHTML(match[1])
		default:
			slog.Error("unknown responder decoder", slog.String("decoder", rule.ResponderDecoder))
		}

		if final_match == "" {
			return strings.Replace(string(content.Data), responder.LLMReplacementTag, responder.LLMReplacementFallbackString, 1)
		}

		body, err := s.llmResponder.Respond(rule.Responder, final_match, string(content.Data))
		if err != nil {
			slog.Error("error responding", slog.String("match", final_match), slog.String("error", err.Error()))
		}
		return body
	}
	// Remove the tag and send the template as-is
	return strings.Replace(string(content.Data), responder.LLMReplacementTag, responder.LLMReplacementFallbackString, 1)
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
			slog.Error("error starting session", slog.String("ip", sReq.SourceIP), slog.String("error", err.Error()))
		} else {
			session.LastRuleServed.AppID = -1
		}
	}

	allowRequest, err := s.rateLimiter.AllowRequest(sReq)
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
		case ratelimit.ErrIPBucketLimitExceeded:
			evt.Subtype = constants.IpEventSubTypeRateIPBucket
			s.metrics.rateLimiterRejects.WithLabelValues(RatelimiterRejectReasonIPBucket).Add(1)
		case ratelimit.ErrIPWindowLimitExceeded:
			evt.Subtype = constants.IpEventSubTypeRateIPWindow
			s.metrics.rateLimiterRejects.WithLabelValues(RatelimiterRejectReasonIPWindow).Add(1)
		case ratelimit.ErrURIBucketLimitExceeded:
			evt.Subtype = constants.IpEventSubTypeRateURIBucket
			s.metrics.rateLimiterRejects.WithLabelValues(RatelimiterRejectReasonURIBucket).Add(1)
		case ratelimit.ErrURIWindowLimitExceeded:
			evt.Subtype = constants.IpEventSubTypeRateURIWindow
			s.metrics.rateLimiterRejects.WithLabelValues(RatelimiterRejectReasonURIWindow).Add(1)

		default:
			slog.Error("error happened in ratelimiter", slog.String("error", err.Error()))
		}

		s.ipEventManager.AddEvent(evt)

		slog.Debug("ratelimiter blocked request", slog.String("ip", sReq.SourceIP), slog.String("honeypoyt", sReq.HoneypotIP), slog.String("error", err.Error()))
		return nil, status.Errorf(codes.ResourceExhausted, "ratelimiter blocked request: %s", err)
	}

	s.metrics.requestsPerPort.WithLabelValues(fmt.Sprintf("%d", sReq.Port)).Add(1)
	s.metrics.methodPerRequest.WithLabelValues(sReq.Method).Add(1)
	s.metrics.honeypotRequests.WithLabelValues(sReq.HoneypotIP).Add(1)
	s.metrics.reqsQueueGauge.Set(float64(len(s.reqsQueue)))

	matchedRule, err := s.GetMatchedRule(s.safeRules.Get(), sReq, session)

	// If there was no matche rule then serve the default rule of the honeypot.
	if err != nil {
		hp, err := s.getCachedHoneypot(sReq.HoneypotIP)

		if hp == nil {
			if err != nil {
				slog.Error("error finding honeypot", slog.String("error", err.Error()), slog.String("honeypot", sReq.HoneypotIP))
			} else {
				slog.Error("honeypot does not exist ?", slog.String("honeypot", sReq.HoneypotIP))
			}
			matchedRule = s.safeRules.Get()[0]
		} else {
			// Fallback to an empty rule.
			matchedRule.ContentID = hp.DefaultContentID
			matchedRule.AppID = 0
			matchedRule.ID = 0
		}
	} else {
		if matchedRule.Alert {
			s.alertMgr.SendBufferedMessage(fmt.Sprintf("Rule ID: %d, URI: %s", matchedRule.ID, sReq.Uri))
		}
	}

	if matchedRule.Block {
		return nil, status.Errorf(codes.PermissionDenied, "Rule blocks request")
	}

	sReq.ContentID = matchedRule.ContentID
	sReq.RuleID = matchedRule.ID
	sReq.AppID = matchedRule.AppID
	sReq.RuleUuid = matchedRule.ExtUuid
	sReq.SessionID = session.ID

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

	slog.Debug("Fetching content", slog.Int64("content_id", matchedRule.ContentID))
	content, err := s.dbClient.GetContentByID(matchedRule.ContentID)
	if err != nil {
		slog.Error("error getting content", slog.String("honeypot", sReq.HoneypotIP), slog.Int64("content_id", matchedRule.ContentID), slog.String("error", err.Error()))
		return nil, status.Errorf(codes.Unavailable, "fetching content ID %d: %s", matchedRule.ContentID, err)
	}

	res := &backend_service.HttpResponse{}
	res.StatusCode = content.StatusCode
	if content.Script != "" {
		slog.Debug("running script")
		err := s.jRunner.RunScript(content.Script, *sReq, res, colEx, false)
		if err != nil {
			slog.Warn("couldn't run script", slog.String("error", err.Error()))
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
			res.Body = []byte(s.getResponderData(sReq, &matchedRule, &content))
			sReq.RawResponse = string(res.Body)
		} else {
			res.Body = content.Data
		}
	}

	// Apply the templating and render the macros after the scripts have run. This
	// allows scripts to also output macros.
	templr := templator.NewTemplator()
	if templr == nil {
		slog.Error("templator is not initialized")
	} else {
		newBody, err := templr.RenderTemplate(res.Body)
		if err != nil {
			slog.Error("error rendering template", slog.String("error", err.Error()))
		} else {
			res.Body = newBody
		}
	}

	// Append custom headers
	res.Header = append(res.Header, &backend_service.KeyValue{
		Key:   "Content-type",
		Value: content.ContentType,
	})
	res.Header = append(res.Header, &backend_service.KeyValue{
		Key:   "Server",
		Value: content.Server,
	})

	for _, header := range content.Headers {
		headerParts := strings.SplitN(header, ": ", 2)
		if len(headerParts) != 2 {
			slog.Warn("Invalid header for content ID", slog.String("header", header), slog.Int64("content_id", content.ID))
			continue
		}

		headerValue := headerParts[1]
		newHdr, err := templr.RenderTemplate([]byte(headerParts[1]))
		if err != nil {
			slog.Error("error rendering template for header", slog.String("error", err.Error()), slog.String("header", headerParts[1]))
		} else {
			headerValue = string(newHdr)
		}
		res.Header = append(res.Header, &backend_service.KeyValue{
			Key:   headerParts[0],
			Value: headerValue,
		})
	}

	s.metrics.rpcResponseTime.Observe(time.Since(rpcStartTime).Seconds())

	return &backend_service.HandleProbeResponse{
		Response: res,
	}, nil
}

// LoadRules loads the content rules from the database.
func (s *BackendServer) LoadRules() error {

	const (
		rulesBatchSize   = 1000
		maxBatchesToLoad = 10
	)

	rulesOffset := 0
	var allRules []models.ContentRule

	for i := 0; i < maxBatchesToLoad; i += 1 {
		rules, err := s.dbClient.SearchContentRules(int64(rulesOffset), int64(rulesBatchSize), "enabled:true")
		if err != nil {
			return err
		}

		allRules = append(allRules, rules...)

		// If there are fewer rules than in a batch, we are done.
		if len(rules) < rulesBatchSize {
			break
		}

		rulesOffset += rulesBatchSize
	}

	s.safeRules.Set(allRules)
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

	dm, err := s.dbClient.Insert(req)
	if err != nil {
		return fmt.Errorf("error saving request: %s", err)
	}

	if s.describer != nil {
		err := s.describer.MaybeAddNewHash(req.CmpHash, dm.(*models.Request))
		if err != nil {
			slog.Error("error adding new hash", slog.String("error", err.Error()))
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
				RequestID:     dm.ModelID(),
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
				RequestID:     dm.ModelID(),
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
				RequestID:     dm.ModelID(),
				HoneypotIP:    req.HoneypotIP,
			})
		}
	}

	downloadsScheduled := 0
	pingsScheduled := 0

	eCollector.IterateMetadata(dm.ModelID(), func(m *models.RequestMetadata) error {

		switch m.Type {
		case constants.ExtractorTypeLink:
			if downloadsScheduled <= maxUrlsToExtractForDownload {
				ipBasedUrl, ip, hostHeader, err := ConvertURLToIPBased(m.Data)
				if err != nil {
					slog.Warn("error converting URL", slog.String("url", m.Data), slog.String("error", err.Error()))
				} else {
					s.ScheduleDownloadOfPayload(req.SourceIP, req.HoneypotIP, m.Data, ip, ipBasedUrl, hostHeader, dm.ModelID())
					downloadsScheduled += 1
				}
			} else {
				slog.Warn("skipping download due to excessive links", slog.String("url", m.Data))
			}

		case constants.ExtractorTypePing:

			if pingsScheduled <= maxPingsToExtract {
				parts := strings.Split(m.Data, " ")
				if len(parts) != 2 {
					slog.Error("invalid ping request", slog.String("data", m.Data))
				} else {
					cnt, err := strconv.Atoi(parts[1])
					if err != nil {
						slog.Error("invalid ping count", slog.String("data", m.Data))
						cnt = 3
					}
					s.SchedulePingOfAddress(req.HoneypotIP, parts[0], int64(cnt), m.RequestID)
				}

			} else {
				slog.Warn("skipping ping due to excessive amount", slog.String("ping", m.Data))
			}
		}

		_, err := s.dbClient.Insert(m)
		if err != nil {
			slog.Warn("Could not save metadata for request", slog.String("error", err.Error()))
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
