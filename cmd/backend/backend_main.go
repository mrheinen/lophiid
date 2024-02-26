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
	"loophid/pkg/alerting"
	"loophid/pkg/backend"
	"loophid/pkg/database"
	"loophid/pkg/downloader"
	"loophid/pkg/javascript"
	"loophid/pkg/vt"
	"loophid/pkg/whois"
	"net"
	"net/http"
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

// Alerting flags
var alertInterval = flag.Int("alert-interval", 2, "Alert every <interval> minutes")
var tgApiKey = flag.String("alert-tg-apikey", "", "Telegram API key")
var tgChannelId = flag.Int64("alert-tg-chanid", 0, "Telegram channel ID")

// Virustotal flags
var vtApiKey = flag.String("vt-apikey", "", "Virustotal API key")

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

	alertMgr := alerting.NewAlertManager(*alertInterval)
	alertMgr.AddAlerter(alerting.NewLogAlerter())

	// Enable the telegram alerter.
	if *tgApiKey != "" && *tgChannelId != 0 {
		tga := alerting.NewTelegramAlerter(*tgApiKey, *tgChannelId, true)
		if err = alertMgr.AddAlerter(tga); err != nil {
			slog.Error("Error initializing telegram alerter", slog.String("error", err.Error()))
			return
		}
	}

	dbc := database.NewKSQLClient(&db)

	whoisManager := whois.NewCachedWhoisManager(dbc)

	var vtMgr vt.VTManager
	if *vtApiKey == "" {
		vtMgr = nil
	} else {
		// Start the virustotal client/manager
		vtc := vt.NewVTClient(*vtApiKey, time.Hour*96)
		vtc.Start()

		vtMgr = vt.NewVTBackgroundManager(dbc, vtc)
		vtMgr.Start()
	}

	jRunner := javascript.NewGojaJavascriptRunner()

	// Create the downloader
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: time.Minute * 10}

	dLoader := downloader.NewHTTPDownloader(*downloadDir, client)

	queryRunner := backend.NewQueryRunnerImpl(dbc)
	bs := backend.NewBackendServer(dbc, dLoader, jRunner, alertMgr, vtMgr, whoisManager, queryRunner)
	if err = bs.Start(); err != nil {
		slog.Error("Error: %s", err)
	}

	if *serverCert == "" {
		rpcServer := grpc.NewServer()
		backend_service.RegisterBackendServiceServer(rpcServer, bs)
		if err = rpcServer.Serve(listener); err != nil {
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
