package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"loophid/backend_service"
	"loophid/pkg/backend"
	"loophid/pkg/database"
	"net"
	"os"

	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
	"google.golang.org/grpc"
)

var serverLocation = flag.String("s", "localhost:41110", "RPC server listen string")

func main() {

	var programLevel = new(slog.LevelVar) // Info by default
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: programLevel})
	slog.SetDefault(slog.New(h))
	programLevel.Set(slog.LevelDebug)
	listener, err := net.Listen("tcp", *serverLocation)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	connectString := "postgres://lo:test@localhost/lophiid"
	db, err := kpgx.New(context.Background(), connectString, ksql.Config{
		MaxOpenConns: 3,
	})
	if err != nil {
		fmt.Printf("Error opening database: %s", err)
		return
	}

	dbc := database.NewKSQLClient(&db)

	bs := backend.NewBackendServer(dbc)
	if err := bs.Start(); err != nil {
		fmt.Printf("Error: %s", err)
	}

	rpcServer := grpc.NewServer()
	backend_service.RegisterBackendServiceServer(rpcServer, bs)
	if err := rpcServer.Serve(listener); err != nil {
		fmt.Printf("Error: %s\n", err)
	}
}
