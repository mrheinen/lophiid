package backend

import (
	"context"
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
}

func NewBackendServer(c database.DatabaseClient) *BackendServer {
	return &BackendServer{
		dbClient:      c,
		safeRules:     &SafeRules{},
		safeRulesChan: make(chan bool),
		reqsQueue:     &RequestQueue{},
	}
}

func (s *BackendServer) HandleProbe(ctx context.Context, req *backend_service.HandleProbeRequest) (*backend_service.HandleProbeResponse, error) {
	slog.Info("Got request", slog.String("uri", req.GetRequestUri()), slog.String("method", req.GetRequest().GetMethod()))

	sReq := database.Request{
		Proto:         req.GetRequest().GetProto(),
		Method:        req.GetRequest().GetMethod(),
		Uri:           req.GetRequestUri(),
		Path:          req.GetRequest().GetParsedUrl().GetPath(),
		Port:          req.GetRequest().GetParsedUrl().GetPort(),
		ContentLength: req.GetRequest().GetContentLength(),
		Body:          req.GetRequest().GetBody(),
		Raw:           req.GetRequest().GetRaw(),
	}
	remoteAddrParts := strings.Split(req.GetRequest().GetRemoteAddress(), ":")
	if len(remoteAddrParts) == 2 {
		sReq.SourceIP = remoteAddrParts[0]
		port, err := strconv.Atoi(remoteAddrParts[1])
		if err != nil {
			slog.Warn("Unable to convert source IP", slog.String("error", err.Error()))
		} else {
			sReq.SourcePort = int64(port)
		}
	}

	// TODO: Add more headers here, in the struct, proto and database.
	for _, h := range req.GetRequest().GetHeader() {
		switch strings.ToLower(h.Key) {
		case "referer":
			sReq.Referer = h.Value
		case "user-agent":
			sReq.UserAgent = h.Value
		}
	}

	// Put it in the queue so it can be stored async in the db.
	s.reqsQueue.Push(&sReq)

	var res *backend_service.HttpResponse
	var matchedRules []database.ContentRule
	for _, rule := range s.safeRules.GetRules() {
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
		return &backend_service.HandleProbeResponse{
			Response: &backend_service.HttpResponse{
				Body: "maybe",
			},
		}, nil
	}

	// Select a random rule if multiple matched.
	matchedRule := matchedRules[0]
	if len(matchedRules) > 1 {
		matchedRule = matchedRules[rand.Int()%len(matchedRules)]
	}

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
		id, err := s.dbClient.InsertRequest(req)
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
