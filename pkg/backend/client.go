package backend

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
	Connect(connectString string, authToken string) error
	HandleProbeRequest(probeRequest *backend_service.HandleProbeRequest) (*backend_service.HandleProbeResponse, error)
	HandleUploadFile(request *backend_service.UploadFileRequest) (*backend_service.UploadFileResponse, error)
	SendSourceContext(req *backend_service.SendSourceContextRequest) (*backend_service.SendSourceContextResponse, error)
	SendStatus(req *backend_service.StatusRequest) (*backend_service.StatusResponse, error)
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
	SendStatusReturnResponse  *backend_service.StatusResponse
	SendStatusReturnError     error
	UploadFileReturnResponse  *backend_service.UploadFileResponse
	UploadFileReturnError     error
	SendSourceContextResponse *backend_service.SendSourceContextResponse
	SendSourceContextError    error
}

func (f *FakeBackendClient) Connect(connectString string, authToken string) error {
	return f.ConnectReturnError
}

func (f *FakeBackendClient) Disconnect() {}

func (f *FakeBackendClient) HandleProbeRequest(probeRequest *backend_service.HandleProbeRequest) (*backend_service.HandleProbeResponse, error) {
	f.CapturedProbeRequest = probeRequest
	return f.HandleProbeReturnResponse, f.HandleProbeReturnError
}

func (f *FakeBackendClient) SendStatus(req *backend_service.StatusRequest) (*backend_service.StatusResponse, error) {
	return f.SendStatusReturnResponse, f.SendStatusReturnError
}

func (f *FakeBackendClient) HandleUploadFile(req *backend_service.UploadFileRequest) (*backend_service.UploadFileResponse, error) {
	return f.UploadFileReturnResponse, f.UploadFileReturnError
}

func (f *FakeBackendClient) SendSourceContext(req *backend_service.SendSourceContextRequest) (*backend_service.SendSourceContextResponse, error) {
	return f.SendSourceContextResponse, f.SendSourceContextError
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

// tokenAuth is a basic token authenticator.
type tokenAuth struct {
	token string
}

func (t tokenAuth) GetRequestMetadata(ctx context.Context, in ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + t.token,
	}, nil
}

func (tokenAuth) RequireTransportSecurity() bool {
	return true
}

func (c *SecureBackendClient) Connect(connectString string, authToken string) error {
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

	c.clientConnect, err = grpc.Dial(connectString,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithPerRPCCredentials(tokenAuth{
			token: authToken,
		}),
	)

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
	return c.backendClient.HandleProbe(context.Background(), probeRequest)
}

func (c *SecureBackendClient) SendStatus(req *backend_service.StatusRequest) (*backend_service.StatusResponse, error) {
	return c.backendClient.SendStatus(context.Background(), req)
}

func (c *SecureBackendClient) HandleUploadFile(req *backend_service.UploadFileRequest) (*backend_service.UploadFileResponse, error) {
	return c.backendClient.HandleUploadFile(context.Background(), req)
}

func (c *SecureBackendClient) SendSourceContext(req *backend_service.SendSourceContextRequest) (*backend_service.SendSourceContextResponse, error) {
	return c.backendClient.SendSourceContext(context.Background(), req)
}

// InsecureBackendClient is a backend client that does not use SSL.
type InsecureBackendClient struct {
	clientConnect *grpc.ClientConn
	backendClient backend_service.BackendServiceClient
}

func (c *InsecureBackendClient) Connect(connectString string, authToken string) error {
	var err error = nil
	c.clientConnect, err = grpc.Dial(connectString, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(tokenAuth{
			token: authToken,
		}))
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
	return c.backendClient.HandleProbe(context.Background(), probeRequest)
}

func (c *InsecureBackendClient) SendStatus(req *backend_service.StatusRequest) (*backend_service.StatusResponse, error) {
	return c.backendClient.SendStatus(context.Background(), req)
}

func (c *InsecureBackendClient) HandleUploadFile(req *backend_service.UploadFileRequest) (*backend_service.UploadFileResponse, error) {
	return c.backendClient.HandleUploadFile(context.Background(), req)
}

func (c *InsecureBackendClient) SendSourceContext(req *backend_service.SendSourceContextRequest) (*backend_service.SendSourceContextResponse, error) {
	return c.backendClient.SendSourceContext(context.Background(), req)
}