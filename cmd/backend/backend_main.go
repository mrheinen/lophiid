package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"loophid/backend_service"
	"loophid/pkg/alerting"
	"loophid/pkg/backend"
	"loophid/pkg/backend/auth"
	"loophid/pkg/database"
	"loophid/pkg/javascript"
	"loophid/pkg/util"
	"loophid/pkg/vt"
	"loophid/pkg/whois"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kkyr/fig"
	lwhois "github.com/likexian/whois"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var configFile = flag.String("c", "", "Config file")

type Config struct {
	Backend struct {
		LogLevel  string `fig:"log_level" default:"debug"`
		LogFile   string `fig:"log_file" validate:"required"`
		RunAsUser string `fig:"user"`
		ChrootDir string `fig:"chroot_dir"`

		Database struct {
			Url                string `fig:"url" validate:"required"`
			MaxOpenConnections int    `fig:"max_open_connections" default:"20"`
			MinOpenConnections int    `fig:"min_open_connections" default:"5"`
		} `fig:"database" validation:"required"`
		Listener struct {
			ListenAddress string `fig:"listen_address" default:"localhost:41110"`
			SSLCert       string `fig:"ssl_cert"`
			SSLKey        string `fig:"ssl_key"`
			CACert        string `fig:"ssl_ca_cert"`
		} `fig:"listener" validate:"required"`
		Downloader struct {
			MalwareDownloadDir string `fig:"malware_download_dir" validate:"required"`
			MaxDownloadSizeMB  int    `fig:"max_download_size_mb" default:"200"`
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
	Metrics struct {
		ListenAddress string `fig:"listen_address" default:"localhost:8998"`
	} `fig:"prometheus"`
	WhoisManager struct {
		ClientTimeout       time.Duration `fig:"client_timeout" default:"2s"`
		CacheExpirationTime time.Duration `fig:"cache_expiration_time" default:"12h"`
		MaxAttempts         int           `fig:"max_attempts" default:"3"`
	} `fig:"whois_manager"`
}

func main() {

	flag.Parse()

	var cfg Config
	if err := fig.Load(&cfg, fig.File(*configFile)); err != nil {
		fmt.Printf("Could not parse config: %s\n", err)
		return
	}

	lf, err := os.OpenFile(cfg.Backend.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Could not open logfile: %s\n", err)
		return
	}

	defer lf.Close()

	teeWriter := util.NewTeeLogWriter([]io.Writer{os.Stdout, lf})

	var programLevel = new(slog.LevelVar) // Info by default
	h := slog.NewTextHandler(teeWriter, &slog.HandlerOptions{Level: programLevel})
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

	metricsRegistry := prometheus.NewRegistry()
	http.Handle("/metrics", promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{Registry: metricsRegistry}))
	go http.ListenAndServe(cfg.Metrics.ListenAddress, nil)

	listener, err := net.Listen("tcp", cfg.Backend.Listener.ListenAddress)
	if err != nil {
		slog.Error("Error: %s\n", err)
		return
	}

	// Create the database handle.
	pgxConf, err := pgxpool.ParseConfig(cfg.Backend.Database.Url)
	if err != nil {
		slog.Error("Error parsing database url: %s", err)
		return
	}

	// Details for the config are here: https://pkg.go.dev/github.com/jackc/pgx/v5/pgxpool#Config
	pgxConf.MaxConns = int32(cfg.Backend.Database.MaxOpenConnections)
	pgxConf.MinConns = int32(cfg.Backend.Database.MinOpenConnections)

	pool, err := pgxpool.NewWithConfig(context.Background(), pgxConf)
	if err != nil {
		slog.Error("Error parsing database config: %s", err)
		return
	}

	db, err := kpgx.NewFromPgxPool(pool)
	if err != nil {
		slog.Error("Error creating database: %s", err)
		return
	}

	dbc := database.NewKSQLClient(&db)

	// Create the alert manager.
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

	whoisClient := lwhois.NewClient()
	whoisClient.SetTimeout(cfg.WhoisManager.ClientTimeout)

	wMetrics := whois.CreateWhoisMetrics(metricsRegistry)
	whoisManager := whois.NewCachedWhoisManager(dbc, wMetrics, whoisClient, cfg.WhoisManager.CacheExpirationTime, cfg.WhoisManager.MaxAttempts)
	whoisManager.Start()

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

		metrics := vt.CreateVTMetrics(metricsRegistry)
		vtMgr = vt.NewVTBackgroundManager(dbc, metrics, vtc)
		vtMgr.Start()
	}

	jRunner := javascript.NewGojaJavascriptRunner(javascript.CreateGoJaMetrics(metricsRegistry))
	queryRunner := backend.NewQueryRunnerImpl(dbc)

	bMetrics := backend.CreateBackendMetrics(metricsRegistry)

	bs := backend.NewBackendServer(dbc, bMetrics, jRunner, alertMgr, vtMgr, whoisManager, queryRunner, cfg.Backend.Downloader.MalwareDownloadDir)
	if err = bs.Start(); err != nil {
		slog.Error("Error: %s", err)
	}

	authCache := util.NewStringMapCache[database.Honeypot]("auth token cache", time.Minute*10)
	authCache.Start()
	auther := auth.NewAuthenticator(dbc, authCache)

	// The following methods do not require authentication. Specifically
	// SendStatus is allowed because it causes new honeypots to be registered by
	// the backend.
	allowListedMethods := []string{"/BackendService/SendStatus"}

	generalGrpcOptions := []grpc.ServerOption{
		grpc.MaxSendMsgSize(1024 * 1024 * 50),
		grpc.MaxRecvMsgSize(1024 * 1024 * cfg.Backend.Downloader.MaxDownloadSizeMB),
		grpc.StreamInterceptor(auth.CustomStreamServerInterceptor(auther.Authenticate, allowListedMethods)),
		grpc.UnaryInterceptor(auth.CustomUnaryServerInterceptor(auther.Authenticate, allowListedMethods)),
	}

	if cfg.Backend.Listener.SSLCert == "" {
		rpcServer := grpc.NewServer(generalGrpcOptions...)
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

	if cfg.Backend.RunAsUser != "" && cfg.Backend.ChrootDir != "" {
		err := util.DropPrivilegesAndChroot(cfg.Backend.RunAsUser, cfg.Backend.ChrootDir)
		if err != nil {
			slog.Warn("Failed to drop privileges and chroot", slog.String("error", err.Error()))
		}
	}

	generalGrpcOptions = append(generalGrpcOptions, grpc.Creds(credentials.NewTLS(tlsConfig)))
	s := grpc.NewServer(generalGrpcOptions...)
	// Register reflection service on gRPC server.
	reflection.Register(s)
	backend_service.RegisterBackendServiceServer(s, bs)
	if err := s.Serve(listener); err != nil {
		slog.Error("Error: %s\n", err)
	}

	// TODO: Implement proper shutdown

}
