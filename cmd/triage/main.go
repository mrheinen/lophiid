package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"lophiid/pkg/analysis"
	"lophiid/pkg/backend"
	"lophiid/pkg/database"
	"lophiid/pkg/llm"
	"lophiid/pkg/triage/describer"
	"lophiid/pkg/util"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kkyr/fig"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
)

var configFile = flag.String("c", "backend-config.json", "Location of the config")
var batchSize = flag.Int64("b", 30, "Amount of descriptions to process at once")
var keepRunning = flag.Bool("r", true, "Whether to keep running continuously")

func main() {
	flag.Parse()

	var cfg backend.Config
	if err := fig.Load(&cfg, fig.File(*configFile)); err != nil {
		fmt.Printf("Could not parse config: %s\n", err)
		return
	}

	lf, err := os.OpenFile(cfg.AI.Triage.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Could not open logfile: %s\n", err)
		return
	}

	defer lf.Close()

	teeWriter := util.NewTeeLogWriter([]io.Writer{os.Stdout, lf})

	var programLevel = new(slog.LevelVar) // Info by default
	h := slog.NewTextHandler(teeWriter, &slog.HandlerOptions{Level: programLevel})
	slog.SetDefault(slog.New(h))

	switch cfg.AI.Triage.LogLevel {
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

	// Handle signals to gracefully exit
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGINT,
		syscall.SIGTERM)
	go func() {
		<-sigc
		slog.Info("Got signal to stop, please wait...")
		*keepRunning = false
	}()

	metricsRegistry := prometheus.NewRegistry()
	http.Handle("/metrics", promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{Registry: metricsRegistry}))
	go func() {
		if err := http.ListenAndServe(cfg.AI.Triage.MetricsListenAddress, nil); err != nil {
			slog.Error("Failed to start metrics server", "error", err)
			os.Exit(1)
		}
	}()

	db, err := kpgx.New(context.Background(), cfg.Backend.Database.Url,
		ksql.Config{
			MaxOpenConns: 10,
		})
	if err != nil {
		slog.Error("error opening database", slog.String("error", err.Error()))
		return
	}
	dbc := database.NewKSQLClient(&db)
	analysisMetrics := analysis.CreateAnalysisMetrics(metricsRegistry)
	ipEventManager := analysis.NewIpEventManagerImpl(dbc, int64(cfg.Analysis.IpEventQueueSize), cfg.Analysis.IpCacheDuration, cfg.Analysis.ScanMonitorInterval, cfg.Analysis.AggregateScanWindow, analysisMetrics)
	ipEventManager.Start()
	deMtrics := describer.CreateDescriberMetrics(metricsRegistry)
	var myDescriber *describer.CachedDescriptionManager

	primaryLLMClient := llm.NewLLMClient(cfg.AI.PrimaryLLM, describer.LLMSystemPrompt)
	if primaryLLMClient == nil {
		slog.Error("Failed to create primary LLM client")
		return
	}

	llmCache := util.NewStringMapCache[string]("LLM prompt cache", cfg.AI.CacheExpirationTime)
	llmMetrics := llm.CreateLLMMetrics(metricsRegistry)
	primaryManager := llm.NewLLMManager(primaryLLMClient, llmCache, llmMetrics, cfg.AI.PrimaryLLM.LLMCompletionTimeout, cfg.AI.PrimaryLLM.LLMConcurrentRequests, true, cfg.AI.PrimaryLLM.PromptPrefix, cfg.AI.PrimaryLLM.PromptSuffix)

	if cfg.AI.SecondaryLLM.ApiKey != "" {
		slog.Info("Secondary LLM configured, using DualLLMManager")
		secondaryLLMClient := llm.NewLLMClient(cfg.AI.SecondaryLLM, describer.LLMSystemPrompt)
		if secondaryLLMClient == nil {
			slog.Error("error creating secondary LLM client")
			return
		}

		secondaryManager := llm.NewLLMManager(secondaryLLMClient, llmCache, llmMetrics, cfg.AI.SecondaryLLM.LLMCompletionTimeout, cfg.AI.SecondaryLLM.LLMConcurrentRequests, true, cfg.AI.SecondaryLLM.PromptPrefix, cfg.AI.SecondaryLLM.PromptSuffix)

		dualManager := llm.NewDualLLMManager(primaryManager, secondaryManager, cfg.AI.FallbackInterval)
		myDescriber = describer.GetNewCachedDescriptionManager(dbc, dualManager, ipEventManager, deMtrics)
	} else {
		slog.Info("Using single primary LLM")
		myDescriber = describer.GetNewCachedDescriptionManager(dbc, primaryManager, ipEventManager, deMtrics)
	}

	for {
		cnt, err := myDescriber.GenerateLLMDescriptions(*batchSize)
		if err != nil {
			// We continue here to not stop the loop
			slog.Error("error generating descriptions", slog.String("error", err.Error()))
		}

		if !*keepRunning {
			slog.Info("Shutting down!")
			return
		}

		// Only sleep when there were no descriptions at all.
		if cnt == 0 {
			time.Sleep(time.Millisecond * 500)
		}
	}
}
