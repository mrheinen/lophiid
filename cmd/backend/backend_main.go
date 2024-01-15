package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"loophid/backend_service"
	"loophid/pkg/backend"
	"loophid/pkg/database"
	"loophid/pkg/downloader"
	"loophid/pkg/javascript"
	"net"
	"os"
	"time"

	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var serverLocation = flag.String("s", "localhost:41110", "RPC server listen string")
var downloadDir = flag.String("d", "/tmp/", "Directory to download files/urls in")
var logLevel = flag.String("v", "debug", "Loglevel (debug, info, warn, error)")
var serverCert = flag.String("ssl-server-cert", "", "server SSL certificate")
var serverKey = flag.String("ssl-server-key", "", "server SSL key")
var caCert = flag.String("ssl-cacert", "", "server CA cert")

func main() {

	flag.Parse()
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

	jRunner := javascript.NewGojaJavascriptRunner()

	dbc := database.NewKSQLClient(&db)
	dLoader := downloader.NewHTTPDownloader(*downloadDir, time.Minute*10)
	bs := backend.NewBackendServer(dbc, dLoader, jRunner)
	if err := bs.Start(); err != nil {
		slog.Error("Error: %s", err)
	}

	if *serverCert == "" {
		rpcServer := grpc.NewServer()
		backend_service.RegisterBackendServiceServer(rpcServer, bs)
		if err := rpcServer.Serve(listener); err != nil {
			slog.Error("Error: %s\n", err)
		}
		return
	}
	// Create tls based credential.
	slog.Info("Creating SSL gRPC server")

	cert, err := tls.LoadX509KeyPair(*serverCert, *serverKey)
	if err != nil {
		log.Fatalf("failed to load key pair: %s", err)
	}

	ca := x509.NewCertPool()
	caBytes, err := os.ReadFile(*caCert)
	if err != nil {
		log.Fatalf("failed to read ca cert %q: %v", *caCert, err)
	}
	if ok := ca.AppendCertsFromPEM(caBytes); !ok {
		log.Fatalf("failed to parse %q", *caCert)
	}

	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    ca,
	}

	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	backend_service.RegisterBackendServiceServer(s, bs)
	if err := s.Serve(listener); err != nil {
		slog.Error("Error: %s\n", err)
	}

}
