package backend

import (
	"context"
	"fmt"
	"log"

	"loophid/backend_service"
	"loophid/pkg/database"
)

type BackendServer struct {
	backend_service.BackendServiceServer
	dbClient database.DatabaseClient
	rules    []database.ContentRule
}

func NewBackendServer(c database.DatabaseClient) *BackendServer {
	return &BackendServer{
		dbClient: c,
	}
}

func (s *BackendServer) HandleProbe(ctx context.Context, req *backend_service.HandleProbeRequest) (*backend_service.HandleProbeResponse, error) {
	log.Printf("Got request: %v", req)

	var res *backend_service.HttpResponse
	var matchedRule *database.ContentRule

	for _, rule := range s.rules {
		reqPath := req.Request.GetParsedUrl().Path
		switch rule.PathMatching {
		case "exact":
			if reqPath == rule.Path {
				matchedRule = &rule
			}
		}

		if matchedRule != nil {
			break
		}
	}

	if matchedRule == nil {
		res = &backend_service.HttpResponse{
			Body: "maybe",
		}
	} else {
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
	}

	return &backend_service.HandleProbeResponse{
		Response: res,
	}, nil
}

func (s *BackendServer) Start() error {
	rules, err := s.dbClient.GetContentRules()
	if err != nil {
		return err
	}
	// TODO: log.info here -> loaded x rules

	s.rules = rules
	return nil
}

func (s *BackendServer) Stop() {
	s.dbClient.Close()
}
