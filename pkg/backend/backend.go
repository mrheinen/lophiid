package backend

import (
	"context"
	"log"
	"net"

	"greyhole/backend_service"

	"google.golang.org/grpc"
)

type BackendServer struct {
	backend_service.BackendServiceServer
	backendServer *grpc.Server
}

func (s *BackendServer) HandleProbe(ctx context.Context, req *backend_service.HandleProbeRequest) (*backend_service.HandleProbeResponse, error) {
	log.Printf("Got request: %v", req)

	// Determine if it is a payload request.
	// If not, send anticipated response.
	res := &backend_service.HttpResponse{
		Body: "hello!",
	}

	return &backend_service.HandleProbeResponse{
		Response: res,
	}, nil
}

func (s *BackendServer) Start(listen_string string) error {
	listener, err := net.Listen("tcp", listen_string)
	if err != nil {
		return err
	}

	s.backendServer = grpc.NewServer()
	backend_service.RegisterBackendServiceServer(s.backendServer, &BackendServer{})
	if err := s.backendServer.Serve(listener); err != nil {
		return err
	}

	log.Printf("Started server on: %s", listen_string)
	return nil
}

func (s *BackendServer) Stop() {
	if s.backendServer != nil {
		s.backendServer.Stop()
	}
}
