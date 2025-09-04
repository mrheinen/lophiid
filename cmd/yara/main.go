package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"lophiid/pkg/backend"
	"lophiid/pkg/database"
	"lophiid/pkg/llm"
	"lophiid/pkg/util"
	"lophiid/pkg/yara"
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

var rulesDir = flag.String("r", "", "Rules directory")
var fileToScan = flag.String("f", "", "File to scan")
var dirToScan = flag.String("d", "", "Directory to scan")
var runManager = flag.Bool("m", false, "Run the manager")
var dbUrl = flag.String("u", "", "Database URL")
var keepRunning = flag.Bool("k", false, "Whether to keep running continuously")
var batchSize = flag.Int64("b", 30, "Amount of downloads to process at once")

func main() {

	flag.Parse()

	var cfg backend.Config
	if err := fig.Load(&cfg, fig.UseEnv("LOPHIID"), fig.IgnoreFile()); err != nil {
		fmt.Printf("Could not parse config: %s\n", err)
		return
	}

	lf, err := os.OpenFile(cfg.Yara.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Could not open logfile: %s\n", err)
		return
	}

	defer lf.Close()

	teeWriter := util.NewTeeLogWriter([]io.Writer{os.Stdout, lf})

	var programLevel = new(slog.LevelVar) // Info by default
	h := slog.NewTextHandler(teeWriter, &slog.HandlerOptions{Level: programLevel})
	slog.SetDefault(slog.New(h))

	switch cfg.Yara.LogLevel {
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

	db, err := kpgx.New(context.Background(), cfg.Backend.Database.Url,
		ksql.Config{
			MaxOpenConns: 5,
		})
	if err != nil {
		slog.Error("error opening database", slog.String("error", err.Error()))
		return
	}

	dbc := database.NewKSQLClient(&db)

	metricsRegistry := prometheus.NewRegistry()
	metrics := yara.CreateYaraMetrics(metricsRegistry)
	if *keepRunning {
		http.Handle("/metrics", promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{Registry: metricsRegistry}))
		go func() {
			if err := http.ListenAndServe(cfg.Yara.MetricsListenAddress, nil); err != nil {
				slog.Error("Failed to start metrics server", "error", err)
				os.Exit(1)
			}
		}()

	}

	llmClient := llm.NewOpenAILLMClientWithModel(cfg.AI.ApiKey, cfg.AI.ApiLocation, "", cfg.AI.Model)
	pCache := util.NewStringMapCache[string]("LLM prompt cache", time.Hour)
	llmMetrics := llm.CreateLLMMetrics(metricsRegistry)
	llmManager := llm.NewLLMManager(llmClient, pCache, llmMetrics, time.Minute*3, 4, true, cfg.AI.PromptPrefix, cfg.AI.PromptSuffix)

	mgr := yara.NewYaraManager(dbc, llmManager, *rulesDir, cfg.Yara.PrepareCommand, metrics)

	yarax := yara.YaraxWrapper{}

	if err := yarax.Init(); err != nil {
		slog.Error("Error initializing yara: ", err)
		return
	}

	if err := yarax.LoadRulesFromDirectory(*rulesDir); err != nil {
		slog.Error("Error loading rules: ", err)
		return
	}

	if *runManager {

		backoffTracker := 1
		maxBackoffRounds := 5
		for {

			cnt, err := mgr.ProcessDownloadsAndScan(*batchSize)
			if err != nil {
				slog.Error("error running manager", slog.String("error", err.Error()))
			}

			if !*keepRunning {
				slog.Info("Shutting down!")
				return
			}

			if cnt == 0 {
				// Sleep increasingly longer
				time.Sleep(time.Millisecond * time.Duration(500*backoffTracker))
				if backoffTracker < maxBackoffRounds {
					backoffTracker += 1
				}
			} else {
				backoffTracker = 0
			}
		}
	}

	if *fileToScan != "" {
		res, err := yarax.ScanFile(*fileToScan)
		if err != nil {
			slog.Error("Error scanning file: ", err)
			return
		}

		yara.PrintYaraResult(*fileToScan, res)

	}

	if *dirToScan != "" {
		err := yarax.ScanDirectoryRecursive(*dirToScan, yara.PrintYaraResult)
		if err != nil {
			slog.Error("Error scanning directory: ", err)
			return
		}
	}
}
