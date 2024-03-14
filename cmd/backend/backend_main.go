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

	"github.com/kkyr/fig"
	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

type Config struct {
	Backend struct {
		LogLevel string `fig:"log_level" default:"debug"`

		Database struct {
			Url                string `fig:"url" validate:"required"`
			MaxOpenConnections int    `fig:"max_open_connections" default:"20"`
		} `fig:"database" validation:"required"`
		Listener struct {
			ListenAddress string `fig:"listen_address" default:"localhost:41110"`
			SSLCert       string `fig:"ssl_cert"`
			SSLKey        string `fig:"ssl_key"`
			CACert        string `fig:"ssl_ca_cert"`
		} `fig:"listener" validate:"required"`
		Downloader struct {
			MalwareDownloadDir string        `fig:"malware_download_dir" validate:"required"`
			HttpClientTimeout  time.Duration `fig:"http_timeout" default:"10m"`
		} `fig:"downloader"`
	} `fig:"backend"`
	Alerting struct {
		Interval time.Duration `fig:"interval" default:"2m"`
		Telegram struct {
			ApiKey    string `fig:"api_key"`
			ChannelID int    `fig:"channel_id"`
		} `fig:"telegram"`
	}
	VirusTotal struct {
		ApiKey            string        `fig:"api_key"`
		HttpClientTimeout time.Duration `fig:"http_timeout" default:"2m"`
	} `fig:"virustotal"`
}

func main() {

	flag.Parse()

	var cfg Config
	if err := fig.Load(&cfg); err != nil {
		fmt.Printf("Could not parse config: %s\n", err)
		return
	}

	var programLevel = new(slog.LevelVar) // Info by default
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: programLevel})
	slog.SetDefault(slog.New(h))

	switch cfg.Backend.LogLevel {
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

	listener, err := net.Listen("tcp", cfg.Backend.Listener.ListenAddress)
	if err != nil {
		slog.Error("Error: %s\n", err)
		return
	}

	db, err := kpgx.New(context.Background(), cfg.Backend.Database.Url, ksql.Config{
		MaxOpenConns: cfg.Backend.Database.MaxOpenConnections,
	})
	if err != nil {
		slog.Error("Error opening database: %s", err)
		return
	}

	alertMgr := alerting.NewAlertManager(cfg.Alerting.Interval)
	alertMgr.AddAlerter(alerting.NewLogAlerter())

	// Enable the telegram alerter.
	if cfg.Alerting.Telegram.ApiKey != "" {
		tga := alerting.NewTelegramAlerter(cfg.Alerting.Telegram.ApiKey, int64(cfg.Alerting.Telegram.ChannelID), true)
		if err = alertMgr.AddAlerter(tga); err != nil {
			slog.Error("Error initializing telegram alerter", slog.String("error", err.Error()))
			return
		}
	}

	dbc := database.NewKSQLClient(&db)
	whoisManager := whois.NewCachedWhoisManager(dbc)

	insecureHttpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	secureHttpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}

	vtHttpClient := &http.Client{Transport: secureHttpTransport, Timeout: cfg.VirusTotal.HttpClientTimeout}

	var vtMgr vt.VTManager
	if cfg.VirusTotal.ApiKey == "" {
		vtMgr = nil
	} else {
		// Start the virustotal client/manager
		vtc := vt.NewVTClient(cfg.VirusTotal.ApiKey, time.Hour*96, vtHttpClient)
		vtc.Start()

		vtMgr = vt.NewVTBackgroundManager(dbc, vtc)
		vtMgr.Start()
	}

	downloadHttpClient := &http.Client{Transport: insecureHttpTransport, Timeout: cfg.Backend.Downloader.HttpClientTimeout}
	dLoader := downloader.NewHTTPDownloader(cfg.Backend.Downloader.MalwareDownloadDir, downloadHttpClient)

	jRunner := javascript.NewGojaJavascriptRunner()

	queryRunner := backend.NewQueryRunnerImpl(dbc)
	bs := backend.NewBackendServer(dbc, dLoader, jRunner, alertMgr, vtMgr, whoisManager, queryRunner)
	if err = bs.Start(); err != nil {
		slog.Error("Error: %s", err)
	}

	if cfg.Backend.Listener.SSLCert == "" {
		rpcServer := grpc.NewServer()
		// Register reflection service on gRPC server.
		reflection.Register(rpcServer)
		backend_service.RegisterBackendServiceServer(rpcServer, bs)

		if err = rpcServer.Serve(listener); err != nil {
			slog.Error("Error: %s\n", err)
		}
		return
	}
	// Create tls based credential.
	slog.Info("Creating SSL gRPC server")

	cert, err := tls.LoadX509KeyPair(cfg.Backend.Listener.SSLCert, cfg.Backend.Listener.SSLKey)
	if err != nil {
		log.Fatalf("failed to load key pair: %s", err)
	}

	ca := x509.NewCertPool()
	caBytes, err := os.ReadFile(cfg.Backend.Listener.CACert)
	if err != nil {
		log.Fatalf("failed to read ca cert %q: %v", cfg.Backend.Listener.CACert, err)
	}
	if ok := ca.AppendCertsFromPEM(caBytes); !ok {
		log.Fatalf("failed to parse %q", cfg.Backend.Listener.CACert)
	}

	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    ca,
	}

	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	// Register reflection service on gRPC server.
	reflection.Register(s)
	backend_service.RegisterBackendServiceServer(s, bs)
	if err := s.Serve(listener); err != nil {
		slog.Error("Error: %s\n", err)
	}

}
