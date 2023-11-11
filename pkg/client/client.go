package client

import (
	"context"
	"fmt"
	"greyhole/backend_service"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type BackendClient interface {
	Connect(connectString string) error
	HandleProbeRequest(probeRequest *backend_service.HandleProbeRequest) error
	Disconnect()
}

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

func (c *InsecureBackendClient) HandleProbeRequest(probeRequest *backend_service.HandleProbeRequest) error {
	resp, err := c.backendClient.HandleProbe(context.Background(), probeRequest)
	if err != nil {
		return err
	}
	fmt.Printf("Receive response => %s ", resp.Message)
	return nil
}
