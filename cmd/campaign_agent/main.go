// Lophiid distributed honeypot
// Copyright (C) 2023-2026 Niels Heinen
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
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lophiid/pkg/bootstrap"
	"lophiid/pkg/campaign"
	"lophiid/pkg/database"
	"lophiid/pkg/llm"
	"lophiid/pkg/util"

	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	backfillMode = flag.Bool("backfill", false, "Enable backfill mode (process historical data)")
	backfillFrom = flag.String("from", "", "Backfill start time (RFC3339, e.g. 2024-01-01T00:00:00Z)")
	backfillTo   = flag.String("to", "", "Backfill end time (RFC3339, e.g. 2024-02-01T00:00:00Z)")
	skipLLM      = flag.Bool("skip-llm", false, "Skip LLM summarization (useful for fast iteration)")
	dryRun       = flag.Bool("dry-run", false, "Run pipeline without writing to the database")
	wipeWindow   = flag.Bool("wipe", false, "Delete existing campaigns in the backfill window before processing (requires --backfill)")
	debugMatch   = flag.Bool("debug-match", false, "Debug why a request matches or doesn't match a campaign")
	debugMerge   = flag.Bool("debug-merge", false, "Debug why two campaigns would or wouldn't merge")
	debugCampID  = flag.Int64("campaign", 0, "Campaign ID for debug modes")
	debugCamp2ID = flag.Int64("campaign2", 0, "Second campaign ID for --debug-merge")
	debugReqID   = flag.Int64("request-id", 0, "Request ID for --debug-match")
)

func main() {
	var cfg campaign.CampaignAgentConfig
	cleanup, err := bootstrap.Initialize(&cfg, bootstrap.InitConfig{
		LogFileExtractor: func(c any) string {
			return c.(*campaign.CampaignAgentConfig).General.LogFile
		},
		LogLevelExtractor: func(c any) string {
			return c.(*campaign.CampaignAgentConfig).General.LogLevel
		},
	})
	if err != nil {
		fmt.Printf("Initialization failed: %s\n", err)
		return
	}
	defer cleanup()

	if err := cfg.Validate(); err != nil {
		slog.Error("invalid configuration", slog.String("error", err.Error()))
		return
	}

	// Initialize database connection.
	ksqlDB, err := kpgx.New(context.Background(), cfg.Database.URL, ksql.Config{
		MaxOpenConns: cfg.Database.MaxOpenConnections,
	})
	if err != nil {
		slog.Error("failed to connect to database", slog.String("error", err.Error()))
		return
	}
	defer ksqlDB.Close()
	dbClient := database.NewKSQLClient(&ksqlDB)

	// Initialize source registry.
	registry, err := campaign.NewSourceRegistry(cfg, dbClient)
	if err != nil {
		slog.Error("failed to create source registry", slog.String("error", err.Error()))
		return
	}

	// Handle debug modes early (no pipeline/LLM needed).
	if *debugMatch || *debugMerge {
		weights := campaign.BuildWeightMap(cfg.Agent.Sources)
		ctx := context.Background()

		// Preload sources so enrichment works for debug-match.
		if *debugMatch {
			registry.PreloadAll(ctx, time.Now().Add(-cfg.Agent.RetroactiveLookback), time.Time{})
		}

		if *debugMatch {
			if *debugCampID == 0 || *debugReqID == 0 {
				fmt.Println("--debug-match requires --campaign and --request-id")
				return
			}
			if err := campaign.DebugMatchRequest(ctx, dbClient, registry, weights, cfg.Agent.SimilarityThreshold, *debugCampID, *debugReqID); err != nil {
				slog.Error("debug-match failed", slog.String("error", err.Error()))
			}
		} else {
			if *debugCampID == 0 || *debugCamp2ID == 0 {
				fmt.Println("--debug-merge requires --campaign and --campaign2")
				return
			}
			if err := campaign.DebugMergeCampaigns(ctx, dbClient, weights, cfg.Agent.SimilarityThreshold, *debugCampID, *debugCamp2ID); err != nil {
				slog.Error("debug-merge failed", slog.String("error", err.Error()))
			}
		}
		return
	}

	// Initialize LLM summarizer.
	var summarizer campaign.Summarizer
	if *skipLLM {
		summarizer = &campaign.NoOpSummarizer{}
		slog.Info("LLM summarization disabled")
	} else if cfg.LLM.LLMConfig != "" {
		llmCfg, err := cfg.GetLLMConfig(cfg.LLM.LLMConfig)
		if err != nil {
			slog.Error("failed to get LLM config", slog.String("error", err.Error()))
			return
		}
		metrics := llm.CreateLLMMetrics(prometheus.DefaultRegisterer)
		llmClient, err := llm.NewLLMClient(llmCfg.PrimaryLLM, "")
		if err != nil {
			slog.Error("failed to create LLM client", slog.String("error", err.Error()))
			return
		}
		pCache := util.NewStringMapCache[string]("", llmCfg.CacheExpirationTime)
		llmManager := llm.NewLLMManager(llmClient, pCache, metrics, llmCfg.CompletionTimeout, llmCfg.ConcurrentRequests, false, llmCfg.PromptPrefix, llmCfg.PromptSuffix)
		summarizer, err = campaign.NewLLMSummarizer(llmManager, cfg.Agent.LLMPrompts.SummarizeTemplate)
		if err != nil {
			slog.Error("failed to create LLM summarizer", slog.String("error", err.Error()))
			os.Exit(1)
		}
	} else {
		summarizer = &campaign.NoOpSummarizer{}
		slog.Warn("no LLM config specified, summarization disabled")
	}

	// Initialize Prometheus metrics.
	pipelineMetrics := campaign.NewPipelineMetrics(prometheus.DefaultRegisterer)
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		slog.Info("metrics server starting", slog.String("address", cfg.Metrics.ListenAddress))
		if err := http.ListenAndServe(cfg.Metrics.ListenAddress, nil); err != nil {
			slog.Error("metrics server failed", slog.String("error", err.Error()))
		}
	}()

	// Create pipeline.
	pipeline := campaign.NewPipeline(dbClient, registry, cfg, summarizer, *dryRun, *skipLLM, *backfillMode)

	// Set up context for graceful shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Info("received signal, shutting down", slog.String("signal", sig.String()))
		cancel()
	}()

	if *wipeWindow && !*backfillMode {
		slog.Error("--wipe requires --backfill mode")
		return
	}

	if *backfillMode {
		fromTime, err := time.Parse(time.RFC3339, *backfillFrom)
		if err != nil {
			slog.Error("invalid --from time", slog.String("error", err.Error()))
			return
		}
		toTime, err := time.Parse(time.RFC3339, *backfillTo)
		if err != nil {
			slog.Error("invalid --to time", slog.String("error", err.Error()))
			return
		}
		if !toTime.After(fromTime) {
			slog.Error("--to must be after --from")
			return
		}

		slog.Info("starting campaign agent in backfill mode",
			slog.String("from", fromTime.String()),
			slog.String("to", toTime.String()),
			slog.Bool("skip_llm", *skipLLM),
			slog.Bool("dry_run", *dryRun),
			slog.Bool("wipe", *wipeWindow),
		)

		if *wipeWindow {
			if *dryRun {
				slog.Info("dry-run: would wipe campaigns in window, skipping")
			} else {
				if err := campaign.WipeCampaignsInWindow(dbClient, fromTime, toTime); err != nil {
					slog.Error("wipe failed", slog.String("error", err.Error()))
					return
				}
			}
		}

		if err := campaign.RunBackfill(ctx, pipeline, pipelineMetrics, fromTime, toTime, cfg.Agent.LookbackWindow); err != nil {
			slog.Error("backfill failed", slog.String("error", err.Error()))
		}
	} else {
		slog.Info("starting campaign agent in interval mode",
			slog.Duration("scan_interval", cfg.Agent.ScanInterval),
			slog.Duration("lookback_window", cfg.Agent.LookbackWindow),
			slog.Bool("skip_llm", *skipLLM),
			slog.Bool("dry_run", *dryRun),
		)

		if err := campaign.RunInterval(ctx, pipeline, pipelineMetrics, cfg.Agent.ScanInterval, cfg.Agent.LookbackWindow); err != nil {
			if ctx.Err() == nil {
				slog.Error("interval mode failed", slog.String("error", err.Error()))
			}
		}
	}

	slog.Info("campaign agent shutting down")
}
