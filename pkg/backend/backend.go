package backend

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"time"

	"loophid/backend_service"
	"loophid/pkg/database"
)

type BackendServer struct {
	backend_service.BackendServiceServer
	dbClient      database.DatabaseClient
	safeRules     *SafeRules
	safeRulesChan chan bool
}

func NewBackendServer(c database.DatabaseClient) *BackendServer {
	return &BackendServer{
		dbClient:      c,
		safeRules:     &SafeRules{},
		safeRulesChan: make(chan bool),
	}
}

func (s *BackendServer) HandleProbe(ctx context.Context, req *backend_service.HandleProbeRequest) (*backend_service.HandleProbeResponse, error) {
	log.Printf("Got request: %v", req)

	var res *backend_service.HttpResponse

	var matchedRules []*database.ContentRule
	for _, rule := range s.safeRules.GetRules() {
		reqPath := req.Request.GetParsedUrl().Path
		switch rule.PathMatching {
		case "exact":
			if reqPath == rule.Path {
				matchedRules = append(matchedRules, &rule)
			}
		}
	}

	if len(matchedRules) == 0 {
		return &backend_service.HandleProbeResponse{
			Response: &backend_service.HttpResponse{
				Body: "maybe",
			},
		}, nil
	}

	matchedRule := matchedRules[0]

	// Select a random rule if multiple matched.
	if len(matchedRules) > 1 {
		matchedRule = matchedRules[rand.Int()%len(matchedRules)]
	}

	fmt.Printf("Fetching content ID %d", matchedRule.ContentID)
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

func (s *BackendServer) Start() error {
	// Load the rules once.
	err := s.LoadRules()

	// Setup the reloading.
	ticker := time.NewTicker(time.Second * 60)

	go func() {
		for {
			select {
			case <-s.safeRulesChan:
				ticker.Stop()
				return
			case <-ticker.C:
				cl := len(s.safeRules.GetRules())

				if err = s.LoadRules(); err != nil {
					fmt.Printf("Error reloading rules: %s", err)
				}
				nl := len(s.safeRules.GetRules())

				if cl != nl {
					fmt.Printf("Rules # updated from %d to %d\n", cl, nl)
				}
			}
		}
	}()

	return err
}

func (s *BackendServer) Stop() {
	s.dbClient.Close()
	// Stop the rules loading.
	s.safeRulesChan <- true
}
