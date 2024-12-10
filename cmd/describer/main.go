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
	"os"
	"time"

	"github.com/kkyr/fig"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
)

var configFile = flag.String("c", "backend-config.json", "Location of the config")

func main() {
	flag.Parse()

	var cfg backend.Config
	if err := fig.Load(&cfg, fig.File(*configFile)); err != nil {
		fmt.Printf("Could not parse config: %s\n", err)
		return
	}

	lf, err := os.OpenFile(cfg.AI.DescriberLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Could not open logfile: %s\n", err)
		return
	}

	defer lf.Close()

	teeWriter := util.NewTeeLogWriter([]io.Writer{os.Stdout, lf})

	var programLevel = new(slog.LevelVar) // Info by default
	h := slog.NewTextHandler(teeWriter, &slog.HandlerOptions{Level: programLevel})
	slog.SetDefault(slog.New(h))

	switch cfg.AI.DescriberLogLevel {
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

	llmClient := llm.NewOpenAILLMClientWithModel(cfg.AI.ApiKey, cfg.AI.ApiLocation, "", cfg.AI.Model)

	metricsRegistry := prometheus.NewRegistry()
	pCache := util.NewStringMapCache[string]("LLM prompt cache", time.Hour)
	llmMetrics := llm.CreateLLMMetrics(metricsRegistry)
	llmManager := llm.NewLLMManager(llmClient, pCache, llmMetrics, time.Minute*3, 4)

	db, err := kpgx.New(context.Background(), cfg.Backend.Database.Url,
		ksql.Config{
			MaxOpenConns: 10,
		})
	if err != nil {
		slog.Error("Error opening database", slog.String("error", err.Error()))
		return
	}

	dbc := database.NewKSQLClient(&db)

	analysisMetrics := analysis.CreateAnalysisMetrics(metricsRegistry)
	ipEventManager := analysis.NewIpEventManagerImpl(dbc, int64(cfg.Analysis.IpEventQueueSize), cfg.Analysis.IpCacheDuration, cfg.Analysis.ScanMonitorInterval, cfg.Analysis.AggregateScanWindow, analysisMetrics)
	ipEventManager.Start()

	deMtrics := describer.CreateDescriberMetrics(metricsRegistry)
	myDescriber := describer.GetNewCachedDescriptionManager(dbc, llmManager, ipEventManager, deMtrics, 10)

	myDescriber.GenerateLLMDescriptions(30)

}
