package backend

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"

	"loophid/backend_service"
	"loophid/pkg/database"
)

type BackendServer struct {
	backend_service.BackendServiceServer
	dbClient        database.DatabaseClient
	safeRules       *SafeRules
	safeRulesChan   chan bool
	reqsProcessChan chan bool
	reqsQueue       *RequestQueue
	sessionCache    *SessionCache
	ruleVsCache     *RuleVsContentCache
}

// NewBackendServer creates a new instance of the backend server.
func NewBackendServer(c database.DatabaseClient) *BackendServer {
	sCache := NewSessionCache(time.Minute * 30)
	rCache := NewRuleVsContentCache(time.Hour * 24 * 30)

	return &BackendServer{
		dbClient:        c,
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

	var res *backend_service.HttpResponse
	var matchedRules []database.ContentRule
	for _, rule := range s.safeRules.GetRules() {
		// Port 0 means any port.
		if rule.Port != 0 && rule.Port != req.GetRequest().GetParsedUrl().GetPort() {
			continue
		}

		reqPath := req.GetRequest().GetParsedUrl().GetPath()

		matched := false
		switch rule.PathMatching {
		case "exact":
			matched = reqPath == rule.Path
		case "prefix":
			matched = strings.HasPrefix(reqPath, rule.Path)
		case "suffix":
			matched = strings.HasSuffix(reqPath, rule.Path)
		case "contains":
			matched = strings.Contains(reqPath, rule.Path)
		case "regex":
			var err error
			matched, err = regexp.MatchString(rule.Path, reqPath)
			// Most cases should be catched when validating a contentrule upon
			// creation.
			if err != nil {
				slog.Warn("Invalid regex", slog.String("error", err.Error()))
			}
		}

		if matched {
			matchedRules = append(matchedRules, rule)
		}
	}

	if len(matchedRules) == 0 {
		// TODO: set this to a default rule
		sReq.ContentID = 0
		sReq.RuleID = 0
		return &backend_service.HandleProbeResponse{
			Response: &backend_service.HttpResponse{
				Body: []byte("maybe"),
			},
		}, nil
	}

	matchedRule := matchedRules[0]
	if len(matchedRules) > 1 {
		lastMatchedRule, err := s.sessionCache.Get(sReq.SourceIP)
		var lastMatchedAppId int64
		if err == nil {
			lastMatchedAppId = lastMatchedRule.AppID
		} else {
			lastMatchedAppId = -1
		}

		matched := false
		var unservedRules []database.ContentRule
		// Find out what rules match but haven't been served.
		for _, r := range matchedRules {
			// We combine the content and rule ID here because some rules can point
			// to the same content but with different settings (e.g. server,
			// content-type) so we want all combinations.
			if !s.ruleVsCache.Has(sReq.SourceIP, r.ID, r.ContentID) {
				unservedRules = append(unservedRules, r)

				// A rule matching the same app id is prefered.
				if r.AppID == lastMatchedAppId {
					matchedRule = r
					matched = true
					break
				}
			}

			if !matched {
				if len(unservedRules) > 0 {
					matchedRule = unservedRules[rand.Int()%len(unservedRules)]
				} else {
					// In this case all rule content combinations have been served at least
					// once to this target. We send a random one.
					matchedRule = matchedRules[rand.Int()%len(matchedRules)]
				}
			}
		}
	}

	// Cache the rule to influence future requests.
	s.sessionCache.CleanExpired()
	s.sessionCache.Store(sReq.SourceIP, matchedRule)
	s.ruleVsCache.Store(sReq.SourceIP, matchedRule.ID, matchedRule.ContentID)

	sReq.ContentID = matchedRule.ContentID
	sReq.RuleID = matchedRule.ID

	slog.Debug("Fetching content", slog.Int64("content_id", matchedRule.ContentID))
	content, err := s.dbClient.GetContentByID(matchedRule.ContentID)
	if err != nil {
		return nil, err
	}

	res = &backend_service.HttpResponse{
		Body:       content.Data,
		StatusCode: content.StatusCode,
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
	s.safeRules.SetRules(rules)
	return nil
}

// ProcessReqsQueue empties the reqsQueue and stores the requests in the
// database. It also extracts metadata from the requests and stores that also in
// the database.
func (s *BackendServer) ProcessReqsQueue() {
	for req := s.reqsQueue.Pop(); req != nil; req = s.reqsQueue.Pop() {
		dm, err := s.dbClient.Insert(req)
		if err != nil {
			slog.Warn("Unable to save request", slog.String("error", err.Error()))
			return
		} else {
			slog.Debug("saved request", slog.Int64("request_id", dm.ModelID()))
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
				RequestID: req.ID,
			})
		}

		for v := range linksMap {
			metadatas = append(metadatas, database.RequestMetadata{
				Type:      lx.MetaType(),
				Data:      string(v),
				RequestID: req.ID,
			})
		}

		// Store the metadata.
		for _, m := range metadatas {
			dm, err := s.dbClient.Insert(&m)
			if err != nil {
				slog.Warn("Could not save metadata for request", slog.String("error", err.Error()))
			} else {
				slog.Debug("Saved metadata", slog.Int64("id", dm.ModelID()), slog.String("value", m.Data), slog.String("type", m.Type))
			}
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

	// Setup the rules reloading.
	rulesTicker := time.NewTicker(time.Second * 60)
	go func() {
		for {
			select {
			case <-s.safeRulesChan:
				rulesTicker.Stop()
				return
			case <-rulesTicker.C:
				cl := len(s.safeRules.GetRules())

				if err = s.LoadRules(); err != nil {
					slog.Error("reloading rules", slog.String("error", err.Error()))
				}
				nl := len(s.safeRules.GetRules())

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

func (s *BackendServer) Stop() {
	// Stop the rules loading.
	s.safeRulesChan <- true
	s.reqsProcessChan <- true
	s.dbClient.Close()
}
