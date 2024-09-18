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
	"lophiid/pkg/database"
	"lophiid/pkg/javascript"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"lophiid/pkg/vt"
	"lophiid/pkg/whois"

	"github.com/vingarcia/ksql"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// User agent to use for downloading.
var userAgent = "Wget/1.13.4 (linux-gnu)"
var maxUrlsToExtractForDownload = 15

type ReqQueueEntry struct {
	req        *database.Request
	rule       database.ContentRule
	eCollector *extractors.ExtractorCollection
}

type BackendServer struct {
	backend_service.BackendServiceServer
	dbClient        database.DatabaseClient
	jRunner         javascript.JavascriptRunner
	qRunner         QueryRunner
	qRunnerChan     chan bool
	vtMgr           vt.VTManager
	whoisMgr        whois.RdapManager
	alertMgr        *alerting.AlertManager
	safeRules       *SafeRules
	maintenanceChan chan bool
	reqsProcessChan chan bool
	reqsQueue       chan ReqQueueEntry
	sessionCache    *util.StringMapCache[database.ContentRule]
	ruleVsCache     *RuleVsContentCache
	downloadQueue   map[string][]backend_service.CommandDownloadFile
	downloadQueueMu sync.Mutex
	downloadsCache  *util.StringMapCache[time.Time]
	metrics         *BackendMetrics
	rateLimiter     ratelimit.RateLimiter
	ipEventManager  analysis.IpEventManager
	config          Config
}

// NewBackendServer creates a new instance of the backend server.
func NewBackendServer(c database.DatabaseClient, metrics *BackendMetrics, jRunner javascript.JavascriptRunner, alertMgr *alerting.AlertManager, vtManager vt.VTManager, wManager whois.RdapManager, qRunner QueryRunner, rateLimiter ratelimit.RateLimiter, ipEventManager analysis.IpEventManager, config Config) *BackendServer {

	sCache := util.NewStringMapCache[database.ContentRule]("content_cache", config.Backend.Advanced.ContentCacheDuration)
	// Setup the download cache and keep entries for 5 minutes. This means that if
	// we get a request with the same download (payload URL) within that time
	// window then we will not download it again.
	dCache := util.NewStringMapCache[time.Time]("download_cache", config.Backend.Advanced.DownloadCacheDuration)
	rCache := NewRuleVsContentCache(config.Backend.Advanced.AttackTrackingDuration)

	return &BackendServer{
		dbClient:        c,
		jRunner:         jRunner,
		qRunner:         qRunner,
		qRunnerChan:     make(chan bool),
		alertMgr:        alertMgr,
		vtMgr:           vtManager,
		whoisMgr:        wManager,
		safeRules:       &SafeRules{},
		maintenanceChan: make(chan bool),
		reqsProcessChan: make(chan bool),
		reqsQueue:       make(chan ReqQueueEntry, config.Backend.Advanced.RequestsQueueSize),
		downloadQueue:   make(map[string][]backend_service.CommandDownloadFile),
		downloadsCache:  dCache,
		sessionCache:    sCache,
		ruleVsCache:     rCache,
		metrics:         metrics,
		config:          config,
		rateLimiter:     rateLimiter,
		ipEventManager:  ipEventManager,
	}
}

func (s *BackendServer) ScheduleDownloadOfPayload(honeypotIP string, originalUrl string, targetIP string, targetUrl string, hostHeader string, requestID int64) bool {

	_, err := s.downloadsCache.Get(originalUrl)
	if err == nil {
		slog.Debug("skipping download as it is in the cache", slog.String("url", originalUrl))
		return false
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
	})
	s.downloadQueueMu.Unlock()
	return true
}

// ProbeRequestToDatabaseRequest transforms aHandleProbeRequest to a
// database.Request.
func (s *BackendServer) ProbeRequestToDatabaseRequest(req *backend_service.HandleProbeRequest) (*database.Request, error) {
	sReq := database.Request{
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

func (s *BackendServer) GetMatchedRule(rules []database.ContentRule, req *database.Request) (database.ContentRule, error) {
	var matchedRules []database.ContentRule
	for _, rule := range rules {
		// Port 0 means any port.
		if rule.Port != 0 && rule.Port != req.Port {
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
		return database.ContentRule{}, fmt.Errorf("no rule found")
	}

	if len(matchedRules) == 1 {
		s.UpdateCaches(req.SourceIP, matchedRules[0])
		return matchedRules[0], nil
	}

	lastMatchedRule, err := s.sessionCache.Get(req.SourceIP)
	var lastMatchedAppId int64
	if err == nil {
		lastMatchedAppId = lastMatchedRule.AppID
	} else {
		lastMatchedAppId = -1
	}

	var unservedRules []database.ContentRule
	// Find out what rules match but haven't been served.
	for _, r := range matchedRules {
		// We combine the content and rule ID here because some rules can point
		// to the same content but with different settings (e.g. server,
		// content-type) so we want all combinations.
		if !s.ruleVsCache.Has(req.SourceIP, r.ID, r.ContentID) {
			unservedRules = append(unservedRules, r)

			// A rule matching the same app id is prefered.
			if r.AppID == lastMatchedAppId {
				s.UpdateCaches(req.SourceIP, r)
				return r, nil
			}
		}
	}

	var matchedRule database.ContentRule

	if len(unservedRules) > 0 {
		matchedRule = unservedRules[rand.Int()%len(unservedRules)]
	} else {
		// In this case all rule content combinations have been served at least
		// once to this target. We send a random one.
		matchedRule = matchedRules[rand.Int()%len(matchedRules)]
	}

	s.UpdateCaches(req.SourceIP, matchedRule)
	return matchedRule, nil
}

func (s *BackendServer) UpdateCaches(ip string, rule database.ContentRule) {
	// Cache the rule to influence future requests.
	// TODO: consider cleaning expired sessions via a go routine.
	s.sessionCache.Store(ip, rule)
	s.ruleVsCache.Store(ip, rule.ID, rule.ContentID)
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
		_, err := s.dbClient.Insert(&database.Honeypot{
			IP:          req.GetIp(),
			Version:     req.GetVersion(),
			LastCheckin: time.Now(),
		})

		if err != nil {
			return &backend_service.StatusResponse{}, status.Errorf(codes.Unavailable, "error inserting honeypot: %s", err)
		}
		slog.Info("status: added honeypot ", slog.String("ip", req.GetIp()))
	} else {
		dms[0].LastCheckin = time.Now()
		dms[0].Version = req.GetVersion()
		if err := s.dbClient.Update(&dms[0]); err != nil {
			return &backend_service.StatusResponse{}, status.Errorf(codes.Unavailable, "error updating honeypot: %s", err)
		}
		slog.Debug("status: updated honeypot ", slog.String("ip", req.GetIp()))
	}

	// Check if there are any downloads scheduled for this honeypot.
	s.downloadQueueMu.Lock()
	defer s.downloadQueueMu.Unlock()
	cmds, ok := s.downloadQueue[req.GetIp()]
	if !ok || len(cmds) == 0 {
		return &backend_service.StatusResponse{}, nil
	}

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
	pr := database.P0fResult{
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

func (s *BackendServer) MaybeExtractLinksFromPayload(fileContent []byte, dInfo database.Download) bool {

	// Check against the reported and detected content type to see if we want to
	// parse this file for URLs.
	if !HasParseableContent(dInfo.UsedUrl, dInfo.ContentType) &&
		!HasParseableContent(dInfo.UsedUrl, dInfo.DetectedContentType) {
		return false
	}

	linksMap := make(map[string]struct{})
	lx := extractors.NewURLExtractor(linksMap)
	lx.ParseString(string(fileContent))

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

			s.ScheduleDownloadOfPayload(dInfo.HoneypotIP, k, ip, ipBasedUrl, hostHeader, dInfo.RequestID)
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
	dInfo := database.Download{}
	dInfo.SHA256sum = fmt.Sprintf("%x", sha256.Sum256(req.GetInfo().GetData()))
	dInfo.UsedUrl = req.GetInfo().GetUrl()
	dInfo.Host = req.GetInfo().GetHostHeader()
	dInfo.ContentType = req.GetInfo().GetContentType()
	dInfo.DetectedContentType = req.GetInfo().GetDetectedContentType()
	dInfo.OriginalUrl = req.GetInfo().GetOriginalUrl()
	dInfo.RequestID = req.RequestId
	dInfo.IP = req.GetInfo().GetIp()
	dInfo.HoneypotIP = req.GetInfo().GetHoneypotIp()
	dInfo.LastRequestID = req.RequestId
	dInfo.TimesSeen = 1
	dInfo.LastSeenAt = time.Now()

	s.metrics.downloadResponseTime.Observe(req.GetInfo().GetDurationSec())

	dms, err := s.dbClient.SearchDownloads(0, 1, fmt.Sprintf("sha256sum:%s", dInfo.SHA256sum))
	if len(dms) == 1 {
		dm := dms[0]
		dm.TimesSeen = dm.TimesSeen + 1
		dm.LastRequestID = req.RequestId
		dm.LastSeenAt = time.Now()
		// Set to the latest HTTP response.
		dm.RawHttpResponse = req.GetInfo().GetRawHttpResponse()

		if err = s.dbClient.Update(&dm); err != nil {
			slog.Warn("could not update", slog.String("error", err.Error()))
		}

		if dm.VTAnalysisMalicious > 0 || dm.VTAnalysisSuspicious > 0 {
			for _, evt := range s.vtMgr.GetEventsForDownload(&dm) {
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

// HandleProbe receives requests from te honeypots and tells them how to
// respond.
func (s *BackendServer) HandleProbe(ctx context.Context, req *backend_service.HandleProbeRequest) (*backend_service.HandleProbeResponse, error) {
	_, ok := auth.GetHoneypotMetadata(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authentication found")
	}

	slog.Info("Got request", slog.String("uri", req.GetRequestUri()), slog.String("method", req.GetRequest().GetMethod()))

	rpcStartTime := time.Now()
	sReq, err := s.ProbeRequestToDatabaseRequest(req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot convert request: %s", err)
	}

	allowRequest, err := s.rateLimiter.AllowRequest(sReq)
	if !allowRequest {

		s.ipEventManager.AddEvent(&database.IpEvent{
			IP:         sReq.SourceIP,
			Type:       constants.IpEventRateLimited,
			Details:    err.Error(),
			Source:     constants.IpEventSourceBackend,
			HoneypotIP: sReq.HoneypotIP,
		})

		switch err {
		case ratelimit.ErrBucketLimitExceeded:
			s.metrics.rateLimiterRejects.WithLabelValues(RatelimiterRejectReasonBucket).Add(1)
		case ratelimit.ErrWindowLimitExceeded:
			s.metrics.rateLimiterRejects.WithLabelValues(RatelimiterRejectReasonWindow).Add(1)
		default:
			slog.Error("error happened in ratelimiter", slog.String("error", err.Error()))
		}

		slog.Debug("ratelimiter blocked request", slog.String("error", err.Error()))
		return nil, status.Errorf(codes.ResourceExhausted, "ratelimiter blocked request: %s", err)
	}

	s.metrics.requestsPerPort.WithLabelValues(fmt.Sprintf("%d", sReq.Port)).Add(1)
	s.metrics.methodPerRequest.WithLabelValues(sReq.Method).Add(1)
	s.metrics.honeypotRequests.WithLabelValues(sReq.HoneypotIP).Add(1)
	s.metrics.reqsQueueGauge.Set(float64(len(s.reqsQueue)))

	matchedRule, err := s.GetMatchedRule(s.safeRules.Get(), sReq)
	if err != nil {
		hps, err := s.dbClient.SearchHoneypots(0, 1, fmt.Sprintf("ip:%s", sReq.HoneypotIP))

		if err != nil || len(hps) == 0 {
			slog.Warn("error finding honeypot", slog.String("error", err.Error()), slog.String("honeypot", sReq.HoneypotIP))
			matchedRule = s.safeRules.Get()[0]
		} else {
			matchedRule.ContentID = hps[0].DefaultContentID
			matchedRule.ID = 0
		}
	} else {
		if matchedRule.Alert {
			s.alertMgr.SendBufferedMessage(fmt.Sprintf("Rule ID: %d, URI: %s", matchedRule.ID, sReq.Uri))
		}
	}

	sReq.ContentID = matchedRule.ContentID
	sReq.RuleID = matchedRule.ID
	sReq.RuleUuid = matchedRule.ExtUuid

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
		return nil, status.Errorf(codes.Unavailable, "fetching content ID %d: %s", matchedRule.ContentID, err)
	}

	res := &backend_service.HttpResponse{}
	res.StatusCode = content.StatusCode
	if content.Script != "" {
		slog.Debug("running script")
		err := s.jRunner.RunScript(content.Script, *sReq, res, false)
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
		res.Body = content.Data
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

		res.Header = append(res.Header, &backend_service.KeyValue{
			Key:   headerParts[0],
			Value: headerParts[1],
		})
	}

	s.metrics.rpcResponseTime.Observe(time.Since(rpcStartTime).Seconds())

	return &backend_service.HandleProbeResponse{
		Response: res,
	}, nil
}

// LoadRules loads the content rules from the database.
func (s *BackendServer) LoadRules() error {
	// TODO: Add logic that allowes only active rules to be selected here

	rulesBatchSize := 1000
	rulesOffset := 0
	maxBatchesToLoad := 10
	var allRules []database.ContentRule

	for i := 0; i < maxBatchesToLoad; i += 1 {
		rules, err := s.dbClient.SearchContentRules(int64(rulesOffset), int64(rulesBatchSize), "")
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

func (s *BackendServer) ProcessRequest(req *database.Request, rule database.ContentRule, eCollector *extractors.ExtractorCollection) error {

	s.whoisMgr.LookupIP(req.SourceIP)

	dm, err := s.dbClient.Insert(req)
	if err != nil {
		return fmt.Errorf("error saving request: %s", err)
	}

	if rule.RequestPurpose != database.RuleRequestPurposeUnknown {
		switch rule.RequestPurpose {
		case database.RuleRequestPurposeAttack:
			s.ipEventManager.AddEvent(&database.IpEvent{
				IP:         req.SourceIP,
				Type:       constants.IpEventAttacked,
				Details:    "rule indicated the IP attacked",
				Source:     constants.IpEventSourceRule,
				SourceRef:  fmt.Sprintf("%d", rule.ID),
				RequestID:  dm.ModelID(),
				HoneypotIP: req.HoneypotIP,
			})
		case database.RuleRequestPurposeCrawl:
			s.ipEventManager.AddEvent(&database.IpEvent{
				IP:         req.SourceIP,
				Type:       constants.IpEventCrawl,
				Source:     constants.IpEventSourceRule,
				SourceRef:  fmt.Sprintf("%d", rule.ID),
				Details:    "rule indicated the IP crawled",
				RequestID:  dm.ModelID(),
				HoneypotIP: req.HoneypotIP,
			})
		case database.RuleRequestPurposeRecon:
			s.ipEventManager.AddEvent(&database.IpEvent{
				IP:         req.SourceIP,
				Source:     constants.IpEventSourceRule,
				SourceRef:  fmt.Sprintf("%d", rule.ID),
				Type:       constants.IpEventRecon,
				Details:    "rule indicated the IP reconned",
				RequestID:  dm.ModelID(),
				HoneypotIP: req.HoneypotIP,
			})
		}
	}

	downloadsScheduled := 0
	eCollector.IterateMetadata(dm.ModelID(), func(m *database.RequestMetadata) error {

		if m.Type == "PAYLOAD_LINK" {
			if downloadsScheduled <= maxUrlsToExtractForDownload {
				ipBasedUrl, ip, hostHeader, err := ConvertURLToIPBased(m.Data)
				if err != nil {
					slog.Warn("error converting URL", slog.String("url", m.Data), slog.String("error", err.Error()))
				} else {
					s.ScheduleDownloadOfPayload(req.HoneypotIP, m.Data, ip, ipBasedUrl, hostHeader, dm.ModelID())
					downloadsScheduled += 1
				}
			} else {
				slog.Warn("skipping download due to excessive links", slog.String("url", m.Data))
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

func (s *BackendServer) loadRuleIdContentIdCombos() error {
	// Load the rule/content ID combos into the cache.
	reqs, err := s.dbClient.GetRequestsDistinctComboLastMonth()
	if err != nil {
		return err
	}

	for _, r := range reqs {
		s.ruleVsCache.Store(r.SourceIP, r.RuleID, r.ContentID)
	}
	return nil
}

func (s *BackendServer) Start() error {
	if err := s.loadRuleIdContentIdCombos(); err != nil {
		return fmt.Errorf("loading combos: %s", err)
	}
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
