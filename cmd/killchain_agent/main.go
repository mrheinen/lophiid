// Lophiid distributed honeypot
// Copyright (C) 2026 Niels Heinen
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
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"lophiid/pkg/backend"
	"lophiid/pkg/backend/rules"
	"lophiid/pkg/database"
	"lophiid/pkg/killchain"
	"lophiid/pkg/llm"
	"lophiid/pkg/util"

	"github.com/kkyr/fig"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
)

var configFile = flag.String("c", "backend-config.yaml", "Location of the config file")
var batchSize = flag.Int64("b", 0, "Batch size override (0 = use config value)")
var keepRunning = flag.Bool("r", true, "Whether to keep running continuously")
var singleSessionID = flag.Int64("s", 0, "Analyse a single session ID and exit")
var dryRun = flag.Bool("dry-run", false, "Perform analysis but skip all DB writes")

func main() {
	flag.Parse()

	var cfg backend.Config
	if err := fig.Load(&cfg, fig.File(*configFile)); err != nil {
		fmt.Printf("Could not parse config: %s\n", err)
		return
	}

	lf, err := os.OpenFile(cfg.AI.KillChain.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Could not open logfile: %s\n", err)
		return
	}
	defer lf.Close()

	teeWriter := util.NewTeeLogWriter([]io.Writer{os.Stdout, lf})

	var programLevel = new(slog.LevelVar)
	h := slog.NewTextHandler(teeWriter, &slog.HandlerOptions{Level: programLevel})
	slog.SetDefault(slog.New(h))

	switch cfg.AI.KillChain.LogLevel {
	case "info":
		programLevel.Set(slog.LevelInfo)
	case "warn":
		programLevel.Set(slog.LevelWarn)
	case "debug":
		programLevel.Set(slog.LevelDebug)
	case "error":
		programLevel.Set(slog.LevelError)
	default:
		programLevel.Set(slog.LevelInfo)
	}

	var running atomic.Bool
	running.Store(*keepRunning)

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc
		slog.Info("Got signal to stop, please wait...")
		running.Store(false)
	}()

	metricsRegistry := prometheus.NewRegistry()
	http.Handle("/metrics", promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{Registry: metricsRegistry}))
	go func() {
		if err := http.ListenAndServe(cfg.AI.KillChain.MetricsListenAddress, nil); err != nil {
			slog.Error("Failed to start metrics server", "error", err)
			os.Exit(1)
		}
	}()

	db, err := kpgx.New(context.Background(), cfg.Backend.Database.Url, ksql.Config{
		MaxOpenConns: 10,
	})
	if err != nil {
		slog.Error("error opening database", slog.String("error", err.Error()))
		return
	}
	dbc := database.NewKSQLClient(&db)

	llmMetrics := llm.CreateLLMMetrics(metricsRegistry)
	killChainLLMCfg, err := cfg.GetLLMConfig(cfg.AI.KillChain.LLMConfig)
	if err != nil {
		slog.Error("error getting kill chain LLM config", slog.String("error", err.Error()))
		return
	}
	llmManager, err := llm.GetLLMManager(killChainLLMCfg, llmMetrics)
	if err != nil {
		slog.Error("error creating LLM manager", slog.String("error", err.Error()))
		return
	}

	safeRules := rules.NewSafeRules(dbc)
	if err := safeRules.Start(cfg.Backend.Advanced.MaintenanceRoutineInterval); err != nil {
		slog.Error("error starting safe rules", slog.String("error", err.Error()))
		return
	}
	defer safeRules.Stop()

	maxRequests := cfg.AI.KillChain.MaxRequests
	maxRequestSize := cfg.AI.KillChain.MaxRequestSize

	analyzer, err := killchain.NewKillChainAnalyzer(dbc, llmManager, safeRules, maxRequests, maxRequestSize, *dryRun)
	if err != nil {
		slog.Error("error creating kill chain analyzer", slog.String("error", err.Error()))
		return
	}

	if *singleSessionID != 0 {
		if analyzeErr := analyzer.AnalyzeSingleSession(*singleSessionID); analyzeErr != nil {
			slog.Error("error analysing session", slog.Int64("session_id", *singleSessionID), slog.String("error", analyzeErr.Error()))
		}
		return
	}

	effectiveBatchSize := int64(cfg.AI.KillChain.BatchSize)
	if *batchSize > 0 {
		effectiveBatchSize = *batchSize
	}

	for {
		cnt, err := analyzer.AnalyzeSessions(effectiveBatchSize)
		if err != nil {
			slog.Error("error during analysis batch", slog.String("error", err.Error()))
		}

		if !running.Load() {
			slog.Info("Shutting down!")
			return
		}

		if cnt == 0 {
			time.Sleep(time.Millisecond * 500)
		}
	}
}
