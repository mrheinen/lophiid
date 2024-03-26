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

	"loophid/backend_service"
	"loophid/pkg/alerting"
	"loophid/pkg/database"
	"loophid/pkg/javascript"
	"loophid/pkg/util"
	"loophid/pkg/vt"
	"loophid/pkg/whois"

	"github.com/vingarcia/ksql"
	//"github.com/vingarcia/ksql"
)

// User agent to use for downloading.
var userAgent = "Wget/1.13.4 (linux-gnu)"

type BackendServer struct {
	backend_service.BackendServiceServer
	dbClient           database.DatabaseClient
	jRunner            javascript.JavascriptRunner
	qRunner            QueryRunner
	qRunnerChan        chan bool
	vtMgr              vt.VTManager
	whoisMgr           whois.WhoisManager
	alertMgr           *alerting.AlertManager
	safeRules          *SafeRules
	safeRulesChan      chan bool
	reqsProcessChan    chan bool
	malwareDownloadDir string
	reqsQueue          chan *database.Request
	sessionCache       *util.StringMapCache[database.ContentRule]
	ruleVsCache        *RuleVsContentCache
	downloadQueue      map[string][]backend_service.CommandDownloadFile
	downloadQueueMu    sync.Mutex
	metrics            *BackendMetrics
}

// NewBackendServer creates a new instance of the backend server.
func NewBackendServer(c database.DatabaseClient, metrics *BackendMetrics, jRunner javascript.JavascriptRunner, alertMgr *alerting.AlertManager, vtManager vt.VTManager, wManager whois.WhoisManager, qRunner QueryRunner, malwareDownloadDir string) *BackendServer {
	sCache := util.NewStringMapCache[database.ContentRule](time.Minute * 30)
	rCache := NewRuleVsContentCache(time.Hour * 24 * 30)

	return &BackendServer{
		dbClient:           c,
		jRunner:            jRunner,
		qRunner:            qRunner,
		qRunnerChan:        make(chan bool),
		alertMgr:           alertMgr,
		vtMgr:              vtManager,
		whoisMgr:           wManager,
		safeRules:          &SafeRules{},
		safeRulesChan:      make(chan bool),
		reqsProcessChan:    make(chan bool),
		reqsQueue:          make(chan *database.Request, 500),
		downloadQueue:      make(map[string][]backend_service.CommandDownloadFile),
		sessionCache:       sCache,
		ruleVsCache:        rCache,
		metrics:            metrics,
		malwareDownloadDir: malwareDownloadDir,
	}
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

	remoteAddrParts := strings.Split(req.GetRequest().GetRemoteAddress(), ":")
	if len(remoteAddrParts) != 2 {
		return nil, fmt.Errorf("IP/port cannot be parsed from : %s", req.GetRequest().GetRemoteAddress())
	}
	sReq.SourceIP = remoteAddrParts[0]
	port, err := strconv.Atoi(remoteAddrParts[1])
	if err != nil {
		return nil, fmt.Errorf("cannot parse IP: %s", err)
	}
	sReq.SourcePort = int64(port)

	// TODO: Add more headers here, in the struct, proto and database.
	for _, h := range req.GetRequest().GetHeader() {
		switch strings.ToLower(h.Key) {
		case "referer":
			sReq.Referer = h.Value
		case "user-agent":
			sReq.UserAgent = h.Value
		}
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
	s.sessionCache.CleanExpired()
	s.sessionCache.Store(ip, rule)
	s.ruleVsCache.Store(ip, rule.ID, rule.ContentID)
}

func (s *BackendServer) SendStatus(ctx context.Context, req *backend_service.StatusRequest) (*backend_service.StatusResponse, error) {
	dm, err := s.dbClient.GetHoneypotByIP(req.GetIp())
	if err != nil {
		_, err := s.dbClient.Insert(&database.Honeypot{
			IP:          req.GetIp(),
			LastCheckin: time.Now(),
		})

		if err != nil {
			return &backend_service.StatusResponse{}, fmt.Errorf("error inserting honeypot: %w", err)
		}
		slog.Info("status: adding honeypot ", slog.String("ip", req.GetIp()))
	} else {
		dm.LastCheckin = time.Now()
		if err := s.dbClient.Update(&dm); err != nil {
			return &backend_service.StatusResponse{}, fmt.Errorf("error updating honeypot: %w", err)
		}
		slog.Info("status: updating honeypot ", slog.String("ip", req.GetIp()))
	}

	// Check if there are any downloads scheduled for this honeypot.
	s.downloadQueueMu.Lock()
	defer s.downloadQueueMu.Unlock()
	cmds, ok := s.downloadQueue[req.GetIp()]
	if !ok || len(cmds) == 0 {
		return &backend_service.StatusResponse{}, nil
	}

	ret := &backend_service.StatusResponse{}
	for idx, _ := range cmds {
		ret.Command = append(ret.Command, &backend_service.Command{
			Command: &backend_service.Command_DownloadCmd{
				DownloadCmd: &cmds[idx],
			},
		})
	}

	delete(s.downloadQueue, req.GetIp())
	return ret, nil
}

func (s *BackendServer) MaybeExtractLinksFromPayload(fileContent []byte, dInfo database.Download) {
	consumableContentTypes := map[string]bool{
		"application/x-shellscript": true,
		"application/x-sh":          true,
		"text/x-sh":                 true,
		"text/plain":                true,
	}

	contentParts := strings.Split(dInfo.ContentType, ";")
	_, hasGoodContent := consumableContentTypes[contentParts[0]]
	if !hasGoodContent &&
		!strings.HasSuffix(dInfo.UsedUrl, ".sh") ||
		!strings.HasSuffix(dInfo.UsedUrl, ".pl") ||
		!strings.HasSuffix(dInfo.UsedUrl, ".bat") ||
		!strings.HasSuffix(dInfo.UsedUrl, ".py") {
		return
	}

	linksMap := make(map[string]struct{})
	lx := NewURLExtractor(linksMap)
	lx.ParseString(string(fileContent))

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

		if host == dInfo.Host {
			slog.Info("Downloading link from payload", slog.String("url", k))

			ipBasedUrl, ip, hostHeader, err := ConvertURLToIPBased(k)
			if err != nil {
				slog.Warn("error converting URL", slog.String("error", err.Error()))
				continue
			}

			fmt.Printf("XXX Adding EXTRA EXTRA URL to the queue (original: %s, modified: %s)\n", k, ipBasedUrl)
			s.downloadQueueMu.Lock()
			s.downloadQueue[dInfo.HoneypotIP] = append(s.downloadQueue[dInfo.HoneypotIP], backend_service.CommandDownloadFile{
				Url:         ipBasedUrl,
				HostHeader:  hostHeader,
				RequestId:   dInfo.RequestID,
				UserAgent:   userAgent,
				OriginalUrl: k,
				Ip:          ip,
			})
			s.downloadQueueMu.Unlock()
		}
	}
}

func (s *BackendServer) HandleUploadFile(ctx context.Context, req *backend_service.UploadFileRequest) (*backend_service.UploadFileResponse, error) {
	rpcStartTime := time.Now()
	retResponse := &backend_service.UploadFileResponse{}

	slog.Debug("Got upload from URL", slog.Int64("request_id", req.RequestId), slog.String("url", req.GetInfo().GetOriginalUrl()))
	// Store the download information in the database.
	dInfo := database.Download{}
	dInfo.SHA256sum = fmt.Sprintf("%x", sha256.Sum256(req.GetInfo().GetData()))

	s.metrics.downloadResponseTime.Observe(req.GetInfo().GetDurationSec())

	dm, err := s.dbClient.GetDownloadBySum(dInfo.SHA256sum)
	if err == nil {
		dm.TimesSeen = dm.TimesSeen + 1
		dm.LastRequestID = req.RequestId
		dm.LastSeenAt = time.Now()
		// Set to the latest HTTP response.
		dm.RawHttpResponse = req.GetInfo().GetRawHttpResponse()

		if err = s.dbClient.Update(&dm); err != nil {
			slog.Warn("could not update", slog.String("error", err.Error()))
		}

		if s.vtMgr != nil && len(dm.VTURLAnalysisID) == 0 {
			slog.Warn("URL analysis ID is not set!")
			s.vtMgr.QueueURL(dInfo.OriginalUrl)
		}

		slog.Debug("Updated existing entry for URL upload", slog.String("url", req.GetInfo().GetOriginalUrl()))
		s.metrics.fileUploadRpcResponseTime.Observe(time.Since(rpcStartTime).Seconds())
		return &backend_service.UploadFileResponse{}, nil
	}

	if !errors.Is(err, ksql.ErrRecordNotFound) {
		slog.Warn("unexpected database error", slog.String("error", err.Error()))
		return &backend_service.UploadFileResponse{}, fmt.Errorf("unexpected database error: %w", err)
	}

	s.whoisMgr.LookupIP(req.GetInfo().GetIp())

	targetDir := fmt.Sprintf("%s/%d", s.malwareDownloadDir, req.RequestId)
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		// Due to concurrency, it is possible that between the check for whether the
		// directory exists and creating one, the directory is already created.
		// Therefore we double check here that any error during creation is no
		// ErrExist which we'll allow.
		if err := os.Mkdir(targetDir, 0755); err != nil && !os.IsExist(err) {
			return retResponse, err
		}
	}

	targetFile := fmt.Sprintf("%s/%d", targetDir, rand.Intn(100000))
	outFileHandle, err := os.Create(targetFile)
	if err != nil {
		return retResponse, fmt.Errorf("creating file: %s", err)
	}

	bytesWritten, err := io.Copy(outFileHandle, bytes.NewReader(req.GetInfo().GetData()))

	dInfo.Size = bytesWritten
	dInfo.RequestID = req.RequestId
	dInfo.FileLocation = targetFile
	dInfo.ContentType = req.GetInfo().GetContentType()
	dInfo.OriginalUrl = req.GetInfo().GetOriginalUrl()
	dInfo.UsedUrl = req.GetInfo().GetUrl()
	dInfo.Host = req.GetInfo().GetHostHeader()
	dInfo.IP = req.GetInfo().GetIp()
	dInfo.HoneypotIP = req.GetInfo().GetHoneypotIp()
	dInfo.LastRequestID = req.RequestId
	dInfo.TimesSeen = 1
	dInfo.LastSeenAt = time.Now()

	_, err = s.dbClient.Insert(&dInfo)
	if err != nil {
		slog.Warn("error on insert", slog.String("error", err.Error()))
		return &backend_service.UploadFileResponse{}, fmt.Errorf("unexpected database error on insert: %w", err)
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
	slog.Info("Got request", slog.String("uri", req.GetRequestUri()), slog.String("method", req.GetRequest().GetMethod()))

	rpcStartTime := time.Now()
	sReq, err := s.ProbeRequestToDatabaseRequest(req)
	if err != nil {
		return nil, err
	}

	s.metrics.requestsPerPort.WithLabelValues(fmt.Sprintf("%d", sReq.Port)).Add(1)
	s.metrics.methodPerRequest.WithLabelValues(sReq.Method).Add(1)
	s.metrics.honeypotRequests.WithLabelValues(sReq.HoneypotIP).Add(1)
	s.metrics.reqsQueueGauge.Set(float64(len(s.reqsQueue)))
	// Put it in the queue so it can be stored async in the db. We don't know if
	// the fetching and serving of content below works. However, we assume it will
	// on purpose so that when a rule has multiple content and one is
	// failing/gone; the next request that matches the rule will be skipping this
	// content.
	s.reqsQueue <- sReq

	matchedRule, err := s.GetMatchedRule(s.safeRules.Get(), sReq)
	if err != nil {
		hp, err := s.dbClient.GetHoneypotByIP(sReq.HoneypotIP)
		if err != nil {
			slog.Warn("error finding honeypot", slog.String("error", err.Error()), slog.String("honeypot", sReq.HoneypotIP))
			matchedRule = s.safeRules.Get()[0]
		} else {
			matchedRule.ContentID = hp.DefaultContentID
			matchedRule.ID = 0
		}
	} else {
		if matchedRule.Alert {
			s.alertMgr.SendBufferedMessage(fmt.Sprintf("Rule ID: %d, URI: %s", matchedRule.ID, sReq.Uri))
		}
	}

	sReq.ContentID = matchedRule.ContentID
	sReq.RuleID = matchedRule.ID

	slog.Debug("Fetching content", slog.Int64("content_id", matchedRule.ContentID))
	content, err := s.dbClient.GetContentByID(matchedRule.ContentID)
	if err != nil {
		return nil, fmt.Errorf("fetching content ID %d: %w", matchedRule.ContentID, err)
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

	s.metrics.rpcResponseTime.Observe(time.Since(rpcStartTime).Seconds())

	return &backend_service.HandleProbeResponse{
		Response: res,
	}, nil
}

// LoadRules loads the content rules from the database.
func (s *BackendServer) LoadRules() error {
	rules, err := s.dbClient.GetContentRules()
	if err != nil {
		return err
	}
	s.safeRules.Set(rules)
	return nil
}

func (s *BackendServer) ProcessReqsQueue() {
	for {
		select {
		case req := <-s.reqsQueue:
			// TODO: consider doing the next line in a goroutine. Doing so might need
			// some of the logic in ProcessRequest to change. For example, the whois
			// lookup will be inefficient when quickly called for the requests from
			// the same IP.
			startTime := time.Now()
			if err := s.ProcessRequest(req); err != nil {
				slog.Warn("process request queue error", slog.String("error", err.Error()))
			}
			s.metrics.reqsQueueResponseTime.Observe(time.Since(startTime).Seconds())

		case <-s.reqsProcessChan:
			slog.Info("Process request queue done")
			return
		}
	}

}

func (s *BackendServer) ProcessRequest(req *database.Request) error {

	s.whoisMgr.LookupIP(req.SourceIP)

	dm, err := s.dbClient.Insert(req)
	if err != nil {
		return fmt.Errorf("error saving request: %s", err)
	}

	// Extract base64 strings
	b64Map := make(map[string][]byte)
	ex := NewBase64Extractor(b64Map, true)
	ex.ParseRequest(req)

	linksMap := make(map[string]struct{})
	lx := NewURLExtractor(linksMap)
	lx.ParseRequest(req)

	if len(b64Map) == 0 && len(linksMap) == 0 {
		return nil
	}

	// Iterate over the base64 strings and store them. Importantly, while doing
	// so try to extract links from the decoded content.
	var metadatas []database.RequestMetadata
	for _, v := range b64Map {
		lx.ParseString(string(v))
		metadatas = append(metadatas, database.RequestMetadata{
			Type:      ex.MetaType(),
			Data:      string(v),
			RequestID: dm.ModelID(),
		})
	}

	// Iterate over the links and try to download them.
	for v := range linksMap {
		ipBasedUrl, ip, hostHeader, err := ConvertURLToIPBased(v)
		if err != nil {
			slog.Warn("error converting URL", slog.String("error", err.Error()))
			continue
		}

		fmt.Printf("XXX Adding URL to the queue (original: %s, modified: %s)\n", v, ipBasedUrl)
		s.downloadQueueMu.Lock()
		s.downloadQueue[req.HoneypotIP] = append(s.downloadQueue[req.HoneypotIP], backend_service.CommandDownloadFile{
			Url:         ipBasedUrl,
			HostHeader:  hostHeader,
			RequestId:   dm.ModelID(),
			UserAgent:   userAgent,
			OriginalUrl: v,
			Ip:          ip,
		})
		s.downloadQueueMu.Unlock()

		metadatas = append(metadatas, database.RequestMetadata{
			Type:      lx.MetaType(),
			Data:      string(v),
			RequestID: dm.ModelID(),
		})
	}

	// Store the metadata.
	for _, m := range metadatas {
		_, err := s.dbClient.Insert(&m)
		if err != nil {
			slog.Warn("Could not save metadata for request", slog.String("error", err.Error()))
		}
	}

	return nil
}

/*
	func (s *BackendServer) DownloadPayload(reqID int64, downloadUrl string, wg *sync.WaitGroup, parseContent bool) {
		consumableContentTypes := map[string]bool{
			"application/x-shellscript": true,
			"application/x-sh":          true,
			"text/x-sh":                 true,
			"text/plain":                true,
		}


		startTime := time.Now()
		dInfo, fileContent, err := s.dLoader.FromUrl(reqID, downloadUrl, outputFile, wg)
		s.metrics.downloadResponseTime.Observe(time.Since(startTime).Seconds())

		if err != nil {
			slog.Debug("could not download", slog.String("error", err.Error()))
			if err = s.dLoader.CleanupTargetFileDir(fmt.Sprintf("%d", reqID), outputFile); err != nil {
				slog.Debug("could not cleanup", slog.String("error", err.Error()))
			}
			return
		}
		slog.Debug("downloaded file", slog.String("file_info", fmt.Sprintf("%v", dInfo)))

		contentParts := strings.Split(dInfo.ContentType, ";")
		_, hasGoodContent := consumableContentTypes[contentParts[0]]
		if parseContent && (hasGoodContent ||
			strings.HasSuffix(dInfo.UsedUrl, ".sh") ||
			strings.HasSuffix(dInfo.UsedUrl, ".pl") ||
			strings.HasSuffix(dInfo.UsedUrl, ".bat") ||
			strings.HasSuffix(dInfo.UsedUrl, ".py")) {
			linksMap := make(map[string]struct{})
			lx := NewURLExtractor(linksMap)
			lx.ParseString(string(fileContent))

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

				if host == dInfo.Host {
					slog.Info("Downloading link from payload", slog.String("url", k))
					wg.Add(1)
					go s.DownloadPayload(reqID, k, wg, false)
				}
			}
		}

		go func(ip string) {
			startTime := time.Now()
			s.whoisMgr.LookupIP(ip)
			s.metrics.whoisResponseTime.Observe(time.Since(startTime).Seconds())
		}(dInfo.IP)

		// Check if we already downloaded this exact file. If we downloaded it
		// before, update the existing database record and increase the
		// times_seen counter. Else add a new record.
		dm, err := s.dbClient.GetDownloadBySum(dInfo.SHA256sum)
		if err == nil {
			dm.TimesSeen = dm.TimesSeen + 1
			dm.LastRequestID = reqID
			dm.LastSeenAt = time.Now()
			// Set to the latest HTTP response.
			dm.RawHttpResponse = dInfo.RawHttpResponse

			if err = s.dLoader.CleanupTargetFileDir(fmt.Sprintf("%d", reqID), outputFile); err != nil {
				slog.Debug("could not cleanup", slog.String("error", err.Error()))
			}
			if err = s.dbClient.Update(&dm); err != nil {
				slog.Warn("could not update", slog.String("error", err.Error()))
			}

			// If the virustotal analysis ID is not set, try to submit the URL.
			if s.vtMgr != nil && len(dm.VTURLAnalysisID) == 0 {
				s.vtMgr.QueueURL(dInfo.OriginalUrl)
			}
		} else {
			if errors.Is(err, ksql.ErrRecordNotFound) {
				dInfo.LastRequestID = reqID
				dInfo.TimesSeen = 1
				dInfo.LastSeenAt = time.Now()
				_, err = s.dbClient.Insert(&dInfo)
				if err != nil {
					slog.Warn("error on insert", slog.String("error", err.Error()))
				}

				if s.vtMgr != nil {
					s.vtMgr.QueueURL(dInfo.OriginalUrl)
				}
			} else {
				slog.Warn("unexpected error", slog.String("error", err.Error()))
			}
		}
	}
*/
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
	rulesTicker := time.NewTicker(time.Second * 60)
	go func() {
		for {
			select {
			case <-s.safeRulesChan:
				rulesTicker.Stop()
				return
			case <-rulesTicker.C:
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

	qRunnerTicker := time.NewTicker(time.Minute * 10)
	go func() {
		for {
			select {
			case <-s.qRunnerChan:
				qRunnerTicker.Stop()
				return
			case <-qRunnerTicker.C:
				start := time.Now()
				if err := s.qRunner.Run(); err != nil {
					slog.Warn("error running queries", slog.String("error", err.Error()))
				}
				s.metrics.qRunnerResponseTime.Observe(time.Since(start).Seconds())
			}
		}
	}()

	return nil
}

func (s *BackendServer) StartRulesLoading() {

}

func (s *BackendServer) Stop() {
	// Stop the rules loading.
	s.safeRulesChan <- true
	s.reqsProcessChan <- true
	s.qRunnerChan <- true
	s.dbClient.Close()
	s.alertMgr.Stop()
}
