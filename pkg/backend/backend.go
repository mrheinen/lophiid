package backend

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"regexp"
	"slices"
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
}

func NewBackendServer(c database.DatabaseClient) *BackendServer {
	return &BackendServer{
		dbClient:        c,
		safeRules:       &SafeRules{},
		safeRulesChan:   make(chan bool),
		reqsProcessChan: make(chan bool),
		reqsQueue:       &RequestQueue{},
	}
}

func (s *BackendServer) HandleProbe(ctx context.Context, req *backend_service.HandleProbeRequest) (*backend_service.HandleProbeResponse, error) {
	slog.Info("Got request", slog.String("uri", req.GetRequestUri()), slog.String("method", req.GetRequest().GetMethod()))

	sReq := database.Request{
		TimeReceived:  time.Unix(req.GetRequest().GetTimeReceived(), 0),
		Proto:         req.GetRequest().GetProto(),
		Method:        req.GetRequest().GetMethod(),
		Uri:           req.GetRequestUri(),
		Path:          req.GetRequest().GetParsedUrl().GetPath(),
		Port:          req.GetRequest().GetParsedUrl().GetPort(),
		ContentLength: req.GetRequest().GetContentLength(),
		Body:          req.GetRequest().GetBody(),
		Raw:           req.GetRequest().GetRaw(),
		HoneypotIP:    req.GetRequest().GetHoneypotIp(),
	}

	defer s.reqsQueue.Push(&sReq)

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
				Body: "maybe",
			},
		}, nil
	}

	matchedRule := matchedRules[0]
	if len(matchedRules) > 1 {
		// TODO: cache this and keep a local version up to date. Maybe update async
		// sync with the database.
		cIdMap, err := s.dbClient.GetRequestUniqueKeyPerSourceIP()
		if err != nil {
			slog.Warn("fetching content table: %s", err.Error())
			// In this case we'll just take a random one.
			matchedRule = matchedRules[rand.Int()%len(matchedRules)]
		} else {
			matched := false
			for _, r := range matchedRules {
				// We combine the content and rule ID here because some rules can point
				// to the same content but with different settings (e.g. server,
				// content-type) so we want all combinations.
				k := fmt.Sprintf("%d-%d", r.ID, r.ContentID)
				if !slices.Contains(cIdMap[sReq.SourceIP], k) {
					matchedRule = r
					matched = true
					break
				}
			}

			if !matched {
				// In this case all rule content combinations have been served at least
				// once to this target. We send a random one.
				matchedRule = matchedRules[rand.Int()%len(matchedRules)]
			}
		}
	}

	// Put it in the queue so it can be stored async in the db. We don't know if
	// the fetching and serving of content below works. However, we assume it will
	// on purpose so that when a rule has multiple content and one is
	// failing/gone; the next request that matches the rule will be skipping this
	// content.
	sReq.ContentID = matchedRule.ContentID
	sReq.RuleID = matchedRule.ID

	// Take all rule IDs.
	// Get all content IDs for source IP in last X time.
	slog.Debug("Fetching content", slog.Int64("content_id", matchedRule.ContentID))
	content, err := s.dbClient.GetContentByID(matchedRule.ContentID)
	if err != nil {
		return nil, err
	}

	res = &backend_service.HttpResponse{
		Body: content.Content,
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

func (s *BackendServer) LoadRules() error {
	rules, err := s.dbClient.GetContentRules()
	if err != nil {
		return err
	}
	s.safeRules.SetRules(rules)
	return nil
}

func (s *BackendServer) ProcessReqsQueue() {
	for req := s.reqsQueue.Pop(); req != nil; req = s.reqsQueue.Pop() {
		id, err := s.dbClient.Insert(req)
		if err != nil {
			slog.Warn("Unable to save request", slog.String("error", err.Error()))
			return
		} else {
			slog.Debug("saved request", slog.Int64("request_id", id))
		}
	}
}

func (s *BackendServer) Start() error {
	// Load the rules once.
	err := s.LoadRules()

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

	return err
}

func (s *BackendServer) Stop() {
	// Stop the rules loading.
	s.safeRulesChan <- true
	s.reqsProcessChan <- true
	s.dbClient.Close()
}
