package backend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"loophid/backend_service"
	"loophid/pkg/alerting"
	"loophid/pkg/database"
	"loophid/pkg/downloader"
	"loophid/pkg/javascript"
	"loophid/pkg/util"
	"loophid/pkg/vt"
	"loophid/pkg/whois"

	"github.com/vingarcia/ksql"
)

type BackendServer struct {
	backend_service.BackendServiceServer
	dbClient        database.DatabaseClient
	dLoader         downloader.Downloader
	jRunner         javascript.JavascriptRunner
	vtMgr           vt.VTManager
	whoisMgr        whois.WhoisManager
	alertMgr        *alerting.AlertManager
	safeRules       *SafeRules
	safeRulesChan   chan bool
	reqsProcessChan chan bool
	reqsQueue       *RequestQueue
	sessionCache    *util.StringMapCache
	ruleVsCache     *RuleVsContentCache
}

// NewBackendServer creates a new instance of the backend server.
func NewBackendServer(c database.DatabaseClient, dLoader downloader.Downloader, jRunner javascript.JavascriptRunner, alertMgr *alerting.AlertManager, vtManager vt.VTManager, wManager whois.WhoisManager) *BackendServer {
	sCache := util.NewStringMapCache(time.Minute * 30)
	rCache := NewRuleVsContentCache(time.Hour * 24 * 30)

	return &BackendServer{
		dbClient:        c,
		dLoader:         dLoader,
		jRunner:         jRunner,
		alertMgr:        alertMgr,
		vtMgr:           vtManager,
		whoisMgr:        wManager,
		safeRules:       &SafeRules{},
		safeRulesChan:   make(chan bool),
		reqsProcessChan: make(chan bool),
		reqsQueue:       &RequestQueue{},
		sessionCache:    sCache,
		ruleVsCache:     rCache,
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
		lastMatchedAppId = lastMatchedRule.(database.ContentRule).AppID
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

	return &backend_service.StatusResponse{}, nil
}

// HandleProbe receives requests from te honeypots and tells them how to
// respond.
func (s *BackendServer) HandleProbe(ctx context.Context, req *backend_service.HandleProbeRequest) (*backend_service.HandleProbeResponse, error) {
	slog.Info("Got request", slog.String("uri", req.GetRequestUri()), slog.String("method", req.GetRequest().GetMethod()))

	sReq, err := s.ProbeRequestToDatabaseRequest(req)
	if err != nil {
		return nil, err
	}

	// Put it in the queue so it can be stored async in the db. We don't know if
	// the fetching and serving of content below works. However, we assume it will
	// on purpose so that when a rule has multiple content and one is
	// failing/gone; the next request that matches the rule will be skipping this
	// content.
	defer s.reqsQueue.Push(sReq)

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

// ProcessReqsQueue empties the reqsQueue and stores the requests in the
// database. It also extracts metadata from the requests and stores that also in
// the database.
func (s *BackendServer) ProcessReqsQueue() error {
	for req := s.reqsQueue.Pop(); req != nil; req = s.reqsQueue.Pop() {

		go func(req *database.Request) {
			s.whoisMgr.LookupIP(req.SourceIP)
		}(req)

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
			continue
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

		var wg sync.WaitGroup
		// Iterate over the links and try to download them.
		for v := range linksMap {
			targetFile, err := s.dLoader.PepareTargetFileDir(fmt.Sprintf("%d", dm.ModelID()))
			if err != nil {
				slog.Warn("error preparing file", slog.String("error", err.Error()))
				continue
			}

			wg.Add(1)
			go s.DownloadPayload(dm.ModelID(), v, targetFile, &wg)
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
		wg.Wait()
	}
	return nil
}

func (s *BackendServer) DownloadPayload(reqID int64, url string, outputFile string, wg *sync.WaitGroup) {
	dInfo, _, err := s.dLoader.FromUrl(reqID, url, outputFile, wg)
	if err != nil {
		slog.Debug("could not download", slog.String("error", err.Error()))
		if err = s.dLoader.CleanupTargetFileDir(fmt.Sprintf("%d", reqID), outputFile); err != nil {
			slog.Debug("could not cleanup", slog.String("error", err.Error()))
		}
		return
	}
	slog.Debug("downloaded file", slog.String("file_info", fmt.Sprintf("%v", dInfo)))

	// Check if we already downloaded this exact file. If we downloaded it
	// before, update the existing database record and increase the
	// times_seen counter. Else add a new record.
	dm, err := s.dbClient.GetDownloadBySum(dInfo.SHA256sum)
	if err == nil {
		dm.TimesSeen = dm.TimesSeen + 1
		dm.LastRequestID = reqID
		if err = s.dLoader.CleanupTargetFileDir(fmt.Sprintf("%d", reqID), outputFile); err != nil {
			slog.Debug("could not cleanup", slog.String("error", err.Error()))
		}
		if err = s.dbClient.Update(&dm); err != nil {
			slog.Warn("could not update", slog.String("error", err.Error()))
		}

		// If the virustotal analysis ID is not set, try to submit the URL.
		if s.vtMgr != nil && len(dm.VTAnalysisID) == 0 {
			s.vtMgr.QueueURL(dInfo.OriginalUrl)
		}
	} else {
		if errors.Is(err, ksql.ErrRecordNotFound) {
			dInfo.LastRequestID = reqID
			dInfo.TimesSeen = 1
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

	// Setup the requests processing
	reqsTicker := time.NewTicker(time.Second * 10)
	go func() {
		for {
			select {
			case <-s.reqsProcessChan:
				reqsTicker.Stop()
				return
			case <-reqsTicker.C:
				s.ProcessReqsQueue()
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
	s.dbClient.Close()
	s.alertMgr.Stop()
}
