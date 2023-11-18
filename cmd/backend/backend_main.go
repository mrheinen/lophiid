package main

import (
	"flag"
	"fmt"
	"loophid/backend_service"
	"loophid/pkg/backend"
	"loophid/pkg/database"
	"net"

	"google.golang.org/grpc"
)

var serverLocation = flag.String("s", "localhost:41110", "RPC server listen string")

func main() {

	listener, err := net.Listen("tcp", *serverLocation)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	dbc := database.PostgresClient{}
	// TODO: make flags
	err = dbc.Init("postgres://lo:test@localhost/lophiid")
	if err != nil {
		fmt.Printf("Error opening database: %s", err)
		return
	}

	bs := backend.NewBackendServer(&dbc)
	if err := bs.Start(); err != nil {
		fmt.Printf("Error: %s", err)
	}

	rpcServer := grpc.NewServer()
	backend_service.RegisterBackendServiceServer(rpcServer, bs)
	if err := rpcServer.Serve(listener); err != nil {
		fmt.Printf("Error: %s\n", err)
	}
}
