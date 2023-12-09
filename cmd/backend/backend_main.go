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
var logLevel = flag.String("v", "debug", "Loglevel (debug, info, warn, error)")

func main() {

	var programLevel = new(slog.LevelVar) // Info by default
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: programLevel})
	slog.SetDefault(slog.New(h))

	switch *logLevel {
	case "info":
		programLevel.Set(slog.LevelInfo)
	case "warn":
		programLevel.Set(slog.LevelWarn)
	case "debug":
		programLevel.Set(slog.LevelDebug)
	case "error":
		programLevel.Set(slog.LevelError)
	default:
		fmt.Printf("Unknown log level given. Using info")
		programLevel.Set(slog.LevelInfo)
	}

	listener, err := net.Listen("tcp", *serverLocation)
	if err != nil {
		slog.Error("Error: %s\n", err)
		return
	}

	connectString := "postgres://lo:test@localhost/lophiid"
	db, err := kpgx.New(context.Background(), connectString, ksql.Config{
		MaxOpenConns: 3,
	})
	if err != nil {
		slog.Error("Error opening database: %s", err)
		return
	}

	dbc := database.NewKSQLClient(&db)

	bs := backend.NewBackendServer(dbc)
	if err := bs.Start(); err != nil {
		slog.Error("Error: %s", err)
	}

	rpcServer := grpc.NewServer()
	backend_service.RegisterBackendServiceServer(rpcServer, bs)
	if err := rpcServer.Serve(listener); err != nil {
		slog.Error("Error: %s\n", err)
	}
}
