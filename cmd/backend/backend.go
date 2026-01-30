// Lophiid distributed honeypot
// Copyright (C) 2024 Niels Heinen
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"log/slog"
	"lophiid/backend_service"
	"lophiid/pkg/alerting"
	"lophiid/pkg/analysis"
	"lophiid/pkg/backend"
	"lophiid/pkg/backend/auth"
	"lophiid/pkg/backend/ratelimit"
	"lophiid/pkg/backend/responder"
	"lophiid/pkg/backend/session"
	"lophiid/pkg/bootstrap"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/javascript"
	"lophiid/pkg/llm"
	"lophiid/pkg/llm/code"
	"lophiid/pkg/llm/file"
	"lophiid/pkg/llm/interpreter"
	"lophiid/pkg/llm/shell"
	"lophiid/pkg/llm/sql"
	"lophiid/pkg/triage/describer"
	"lophiid/pkg/triage/preprocess"
	"lophiid/pkg/util"
	"lophiid/pkg/vt"
	"lophiid/pkg/whois"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openrdap/rdap"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	var cfg backend.Config

	cleanup, err := bootstrap.Initialize(&cfg, bootstrap.InitConfig{
		LogFileExtractor: func(c any) string {
			return c.(*backend.Config).Backend.LogFile
		},
		LogLevelExtractor: func(c any) string {
			return c.(*backend.Config).Backend.LogLevel
		},
	})
	if err != nil {
		fmt.Printf("Initialization failed: %s\n", err)
		return
	}
	defer cleanup()

	metricsRegistry := prometheus.NewRegistry()
	http.Handle("/metrics", promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{Registry: metricsRegistry}))
	go http.ListenAndServe(cfg.Metrics.ListenAddress, nil)

	listener, err := net.Listen("tcp", cfg.Backend.Listener.ListenAddress)
	if err != nil {
		slog.Error("Error listening", slog.String("error", err.Error()))
		return
	}

	// Create the database handle.
	pgxConf, err := pgxpool.ParseConfig(cfg.Backend.Database.Url)
	if err != nil {
		slog.Error("Error parsing database config", slog.String("error", err.Error()))
		return
	}

	// Details for the config are here: https://pkg.go.dev/github.com/jackc/pgx/v5/pgxpool#Config
	pgxConf.MaxConns = int32(cfg.Backend.Database.MaxOpenConnections)
	pgxConf.MinConns = int32(cfg.Backend.Database.MinOpenConnections)

	pool, err := pgxpool.NewWithConfig(context.Background(), pgxConf)
	if err != nil {
		slog.Error("Error creating database pool", slog.String("error", err.Error()))
		return
	}

	db, err := kpgx.NewFromPgxPool(pool)
	if err != nil {
		slog.Error("Error creating KSQL client", slog.String("error", err.Error()))
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

	rdapClient := &rdap.Client{
		HTTP: &http.Client{Timeout: cfg.WhoisManager.ClientTimeout},
	}

	wMetrics := whois.CreateWhoisMetrics(metricsRegistry)
	whoisManager := whois.NewCachedRdapManager(dbc, wMetrics, rdapClient, cfg.WhoisManager.CacheExpirationTime, cfg.WhoisManager.MaxAttempts)
	whoisManager.Start()

	secureHttpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}

	vtHttpClient := &http.Client{Transport: secureHttpTransport, Timeout: cfg.VirusTotal.HttpClientTimeout}

	analysisMetrics := analysis.CreateAnalysisMetrics(metricsRegistry)
	ipEventManager := analysis.NewIpEventManagerImpl(dbc, int64(cfg.Analysis.IpEventQueueSize), cfg.Analysis.IpCacheDuration, cfg.Analysis.ScanMonitorInterval, cfg.Analysis.AggregateScanWindow, analysisMetrics)
	ipEventManager.Start()

	var vtMgr vt.VTManager
	if cfg.VirusTotal.ApiKey == "" {
		vtMgr = nil
	} else {
		// Start the virustotal client/manager
		vtc := vt.NewVTClient(cfg.VirusTotal.ApiKey, cfg.VirusTotal.CacheExpirationTime, vtHttpClient)
		vtc.Start()

		metrics := vt.CreateVTMetrics(metricsRegistry)

		vtMgr = vt.NewVTBackgroundManager(dbc, ipEventManager, metrics, vtc)
		vtMgr.Start()
	}

	queryRunner := backend.NewQueryRunnerImpl(dbc)
	bMetrics := backend.CreateBackendMetrics(metricsRegistry)
	rMetrics := ratelimit.CreateRatelimiterMetrics(metricsRegistry)

	ipRateLimiter := ratelimit.NewWindowRateLimiter(ratelimit.WindowRateLimiterConfig{
		Name:                 "ip",
		RateWindow:           cfg.Backend.RateLimiter.SessionIPRateWindow,
		BucketDuration:       cfg.Backend.RateLimiter.SessionIPBucketDuration,
		MaxRequestsPerWindow: cfg.Backend.RateLimiter.MaxSessionIPRequestsPerWindow,
		MaxRequestPerBucket:  cfg.Backend.RateLimiter.MaxSessionIPRequestsPerBucket,
		Metrics:              rMetrics,
		KeyFunc:              ratelimit.IPKeyFunc,
		BucketExceededErr:    ratelimit.ErrSessionIPBucketLimitExceeded,
		WindowExceededErr:    ratelimit.ErrSessionIPWindowLimitExceeded,
	})
	ipRateLimiter.Start()

	sourceIPRateLimiter := ratelimit.NewWindowRateLimiter(ratelimit.WindowRateLimiterConfig{
		Name:                 "source_ip",
		RateWindow:           cfg.Backend.RateLimiter.SourceIPRateWindow,
		BucketDuration:       cfg.Backend.RateLimiter.SourceIPBucketDuration,
		MaxRequestsPerWindow: cfg.Backend.RateLimiter.MaxSourceIPRequestsPerWindow,
		MaxRequestPerBucket:  cfg.Backend.RateLimiter.MaxSourceIPRequestsPerBucket,
		Metrics:              rMetrics,
		KeyFunc:              ratelimit.SourceIPKeyFunc,
		BucketExceededErr:    ratelimit.ErrSourceIPBucketLimitExceeded,
		WindowExceededErr:    ratelimit.ErrSourceIPWindowLimitExceeded,
	})
	sourceIPRateLimiter.Start()

	uriRateLimiter := ratelimit.NewWindowRateLimiter(ratelimit.WindowRateLimiterConfig{
		Name:                 "uri",
		RateWindow:           cfg.Backend.RateLimiter.URIRateWindow,
		BucketDuration:       cfg.Backend.RateLimiter.URIBucketDuration,
		MaxRequestsPerWindow: cfg.Backend.RateLimiter.MaxURIRequestsPerWindow,
		MaxRequestPerBucket:  cfg.Backend.RateLimiter.MaxURIRequestsPerBucket,
		Metrics:              rMetrics,
		KeyFunc:              ratelimit.URIKeyFunc,
		BucketExceededErr:    ratelimit.ErrURIBucketLimitExceeded,
		WindowExceededErr:    ratelimit.ErrURIWindowLimitExceeded,
	})
	uriRateLimiter.Start()

	var llmResponder responder.Responder
	var desClient describer.DescriberClient

	var shellClient shell.ShellClientInterface

	llmMetrics := llm.CreateLLMMetrics(metricsRegistry)
	if cfg.AI.Responder.Enable {
		responderLLMCfg, err := cfg.GetLLMConfig(cfg.AI.Responder.LLMConfig)
		if err != nil {
			slog.Error("error getting responder LLM config", slog.String("error", err.Error()))
			return
		}
		llmManager := llm.GetLLMManager(responderLLMCfg, llmMetrics)
		slog.Info("Creating responder")
		llmResponder = responder.NewLLMResponder(llmManager, cfg.AI.MaxInputCharacters)
	}

	if cfg.AI.Triage.Describer.Enable {
		slog.Info("Creating describer client")
		desClient = describer.GetNewCachedDescriberClient(dbc, cfg.AI.Triage.Describer.CacheExpirationTime)
	}

	if cfg.AI.ShellEmulation.Enable {
		shellLLMCfg, err := cfg.GetLLMConfig(cfg.AI.ShellEmulation.LLMConfig)
		if err != nil {
			slog.Error("error getting shell emulation LLM config", slog.String("error", err.Error()))
			return
		}
		llmManager := llm.GetLLMManager(shellLLMCfg, llmMetrics)
		shellClient = shell.NewShellClient(llmManager, dbc)
	}

	jRunner := javascript.NewGojaJavascriptRunner(dbc, shellClient, cfg.Scripting.AllowedCommands, cfg.Scripting.CommandTimeout, llmResponder, javascript.CreateGoJaMetrics(metricsRegistry))

	sMetrics := session.CreateSessionMetrics(metricsRegistry)
	sessionMgr := session.NewDatabaseSessionManager(dbc, cfg.Backend.Advanced.SessionTrackingTimeout, sMetrics)

	slog.Info("Cleaning up any stale sessions")
	totalSessionsCleaned := 0

	for {
		cnt, err := sessionMgr.CleanupStaleSessions(50)
		if err != nil {
			slog.Error("error cleaning up stale sessions", slog.String("error", err.Error()))
			return
		}

		totalSessionsCleaned += cnt
		if cnt < 50 {
			break
		}
	}
	slog.Info("Cleaned up stale sessions", slog.Int("count", totalSessionsCleaned))

	preprocessLLMCfg, err := cfg.GetLLMConfig(cfg.AI.Triage.PreProcess.LLMConfig)
	if err != nil {
		slog.Error("error getting preprocess LLM config", slog.String("error", err.Error()))
		return
	}
	payloadLLMManager := llm.GetLLMManager(preprocessLLMCfg, llmMetrics)

	var codeEmu code.CodeSnippetEmulatorInterface

	if cfg.AI.CodeEmulation.Enable {
		codeLLMCfg, err := cfg.GetLLMConfig(cfg.AI.CodeEmulation.LLMConfig)
		if err != nil {
			slog.Error("error getting code emulation LLM config", slog.String("error", err.Error()))
			return
		}
		codeLLMManager := llm.GetLLMManager(codeLLMCfg, llmMetrics)
		codeEmu = code.NewCodeSnippetEmulator(codeLLMManager, shellClient, dbc)
	}

	var fileEmu file.FileAccessEmulatorInterface
	if cfg.AI.FileEmulation.Enable {
		fileLLMCfg, err := cfg.GetLLMConfig(cfg.AI.FileEmulation.LLMConfig)
		if err != nil {
			slog.Error("error getting file emulation LLM config", slog.String("error", err.Error()))
			return
		}
		fileLLMManager := llm.GetLLMManager(fileLLMCfg, llmMetrics)
		fileEmu = file.NewFileAccessEmulator(fileLLMManager)
	}

	var sqlEmu sql.SqlInjectionEmulatorInterface
	if cfg.AI.SqlEmulation.Enable {
		sqlLLMCfg, err := cfg.GetLLMConfig(cfg.AI.SqlEmulation.LLMConfig)
		if err != nil {
			slog.Error("error getting SQL emulation LLM config", slog.String("error", err.Error()))
			return
		}
		sqlLLMManager := llm.GetLLMManager(sqlLLMCfg, llmMetrics)
		sqlEmu = sql.NewSqlInjectionEmulator(sqlLLMManager)
	}

	var codeInterpreter interpreter.CodeInterpreterInterface
	if cfg.AI.CodeInterpreter.Enable {
		interLLMCfg, err := cfg.GetLLMConfig(cfg.AI.CodeInterpreter.LLMConfig)
		if err != nil {
			slog.Error("error getting code interpreter LLM config", slog.String("error", err.Error()))
			return
		}
		codeInterpreter = interpreter.NewCodeInterpreter(llm.GetLLMManager(interLLMCfg, llmMetrics), shellClient, dbc)
	}

	preprocMetric := preprocess.CreatePreprocessMetrics(metricsRegistry)
	preproc := preprocess.NewPreProcess(payloadLLMManager, shellClient, codeEmu, fileEmu, sqlEmu, preprocMetric)

	bs := backend.NewBackendServer(dbc, bMetrics, []ratelimit.RateLimiter{ipRateLimiter, uriRateLimiter, sourceIPRateLimiter}, cfg, backend.WithJavascriptRunner(jRunner), backend.WithAlertManager(alertMgr), backend.WithVTManager(vtMgr), backend.WithWhoisManager(whoisManager), backend.WithQueryRunner(queryRunner), backend.WithIpEventManager(ipEventManager), backend.WithResponder(llmResponder), backend.WithSessionManager(sessionMgr), backend.WithDescriber(desClient), backend.WithPreprocessor(preproc), backend.WithCodeInterpreter(codeInterpreter))
	if err = bs.Start(); err != nil {
		slog.Error("error starting backend", slog.String("error", err.Error()))
	}

	authCache := util.NewStringMapCache[models.Honeypot]("auth token cache", time.Minute*10)
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
			slog.Error("error starting backend", slog.String("error", err.Error()))
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
		slog.Error("error starting backend (serve)", slog.String("error", err.Error()))
	}

	// TODO: Implement proper shutdown

}
