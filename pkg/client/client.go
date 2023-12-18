package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"loophid/backend_service"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type BackendClient interface {
	Connect(connectString string) error
	HandleProbeRequest(probeRequest *backend_service.HandleProbeRequest) (*backend_service.HandleProbeResponse, error)
	Disconnect()
}

// FakeBackendClient is a fake backend client that implements the BackendClient
// interface and which is useful for testing.
type FakeBackendClient struct {
	ConnectReturnError        error // Error you want to return or nil
	HandleProbeReturnError    error
	HandleProbeReturnResponse *backend_service.HandleProbeResponse
	HandleProbeCalled         bool
	CapturedProbeRequest      *backend_service.HandleProbeRequest
}

func (f *FakeBackendClient) Connect(connectString string) error {
	return f.ConnectReturnError
}

func (f *FakeBackendClient) Disconnect() {}

func (f *FakeBackendClient) HandleProbeRequest(probeRequest *backend_service.HandleProbeRequest) (*backend_service.HandleProbeResponse, error) {
	f.CapturedProbeRequest = probeRequest
	return f.HandleProbeReturnResponse, f.HandleProbeReturnError
}

// InsecureBackendClient is a backend client that does not use SSL.
type SecureBackendClient struct {
	clientConnect *grpc.ClientConn
	backendClient backend_service.BackendServiceClient
	ClientCert    string
	ClientKey     string
	CACert        string
	ServerFQDN    string
}

func (c *SecureBackendClient) Connect(connectString string) error {
	var err error = nil

	cert, err := tls.LoadX509KeyPair(c.ClientCert, c.ClientKey)
	if err != nil {
		return err
	}

	ca := x509.NewCertPool()
	caBytes, err := os.ReadFile(c.CACert)
	if err != nil {
		return fmt.Errorf("failed to read ca cert %q: %v", c.CACert, err)
	}
	if ok := ca.AppendCertsFromPEM(caBytes); !ok {
		return fmt.Errorf("failed to parse %q", c.CACert)
	}

	tlsConfig := &tls.Config{
		ServerName:   c.ServerFQDN,
		Certificates: []tls.Certificate{cert},
		RootCAs:      ca,
	}

	c.clientConnect, err = grpc.Dial(connectString, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return err
	}

	c.backendClient = backend_service.NewBackendServiceClient(c.clientConnect)
	return nil
}

func (c *SecureBackendClient) Disconnect() {
	c.clientConnect.Close()
}

func (c *SecureBackendClient) HandleProbeRequest(probeRequest *backend_service.HandleProbeRequest) (*backend_service.HandleProbeResponse, error) {
	resp, err := c.backendClient.HandleProbe(context.Background(), probeRequest)
	return resp, err
}

// InsecureBackendClient is a backend client that does not use SSL.
type InsecureBackendClient struct {
	clientConnect *grpc.ClientConn
	backendClient backend_service.BackendServiceClient
}

func (c *InsecureBackendClient) Connect(connectString string) error {
	var err error = nil
	opts := grpc.WithTransportCredentials(insecure.NewCredentials())
	c.clientConnect, err = grpc.Dial(connectString, opts)
	if err != nil {
		return err
	}

	c.backendClient = backend_service.NewBackendServiceClient(c.clientConnect)
	return nil
}

func (c *InsecureBackendClient) Disconnect() {
	c.clientConnect.Close()
}

func (c *InsecureBackendClient) HandleProbeRequest(probeRequest *backend_service.HandleProbeRequest) (*backend_service.HandleProbeResponse, error) {
	resp, err := c.backendClient.HandleProbe(context.Background(), probeRequest)
	return resp, err
}
