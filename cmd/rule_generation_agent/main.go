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
	"log/slog"
	"os"
	"time"

	"lophiid/pkg/bootstrap"
	"lophiid/pkg/database"
	"lophiid/pkg/llm"
	"lophiid/pkg/rulegeneration"
	"lophiid/pkg/util"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
)

var (
	requestID = flag.Int64("request-id", 0, "ID of the request to analyse (required)")
	dryRun    = flag.Bool("dry-run", false, "Run without writing to the database")
)

func main() {
	var cfg rulegeneration.AgentConfig
	cleanup, err := bootstrap.Initialize(&cfg, bootstrap.InitConfig{
		LogFileExtractor: func(c any) string {
			return c.(*rulegeneration.AgentConfig).General.LogFile
		},
		LogLevelExtractor: func(c any) string {
			return c.(*rulegeneration.AgentConfig).General.LogLevel
		},
	})
	if err != nil {
		fmt.Printf("initialization failed: %s\n", err)
		os.Exit(1)
	}
	defer cleanup()

	if *requestID == 0 {
		slog.Error("--request-id is required")
		flag.Usage()
		os.Exit(1)
	}

	ctx := context.Background()

	ksqlDB, err := kpgx.New(ctx, cfg.Database.URL, ksql.Config{
		MaxOpenConns: cfg.Database.MaxOpenConnections,
	})
	if err != nil {
		slog.Error("failed to connect to database", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer ksqlDB.Close()
	dbClient := database.NewKSQLClient(&ksqlDB)

	req, err := dbClient.GetRequestByID(*requestID)
	if err != nil {
		slog.Error("failed to fetch request", slog.Int64("request_id", *requestID), slog.String("error", err.Error()))
		os.Exit(1)
	}

	descs, err := dbClient.SearchRequestDescription(0, 1, fmt.Sprintf("cmp_hash:%s", req.CmpHash))
	if err != nil {
		slog.Error("failed to fetch request description", slog.Int64("request_id", *requestID), slog.String("error", err.Error()))
		os.Exit(1)
	}
	if len(descs) == 0 {
		slog.Error("no request description found for request", slog.Int64("request_id", *requestID))
		os.Exit(1)
	}
	desc := descs[0]

	completionTimeout, err := time.ParseDuration(cfg.LLM.CompletionTimeout)
	if err != nil {
		slog.Error("invalid completion_timeout", slog.String("error", err.Error()))
		os.Exit(1)
	}

	llmConfig := llm.LLMConfig{
		ApiType:                   cfg.LLM.ApiType,
		ApiLocation:               cfg.LLM.ApiLocation,
		ApiKey:                    cfg.LLM.ApiKey,
		Model:                     cfg.LLM.Model,
		Temperature:               cfg.LLM.Temperature,
		OpenRouterReasoningEffort: cfg.LLM.OpenRouterReasoningEffort,
	}

	llmClient, err := llm.NewLLMClient(llmConfig, "")
	if err != nil {
		slog.Error("failed to create LLM client", slog.String("error", err.Error()))
		os.Exit(1)
	}

	metrics := llm.CreateLLMMetrics(prometheus.NewRegistry())
	pCache := util.NewStringMapCache[string]("", 0)
	llmManager := llm.NewLLMManager(llmClient, pCache, metrics, completionTimeout, 1, false, "", "")

	agent, err := rulegeneration.NewAgentFromConfig(ctx, dbClient, llmManager, cfg.WebSearch, cfg.GitHub, *requestID, *dryRun)
	if err != nil {
		slog.Error("failed to create agent", slog.String("error", err.Error()))
		os.Exit(1)
	}

	if err := agent.Process(ctx, req, desc); err != nil {
		slog.Error("agent failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	slog.Info("rule generation agent finished successfully", slog.Int64("request_id", *requestID))
}
