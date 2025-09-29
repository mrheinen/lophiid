package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"lophiid/pkg/backend"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"lophiid/pkg/llm/shell"
	"lophiid/pkg/util"
	"os"

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

	db, err := kpgx.New(context.Background(), cfg.Backend.Database.Url,
		ksql.Config{
			MaxOpenConns: 10,
		})
	if err != nil {
		slog.Error("error opening database", slog.String("error", err.Error()))
		return
	}

	dbc := database.NewKSQLClient(&db)

	primaryLLMClient := llm.NewLLMClient(cfg.AI.PrimaryLLM, "")
	if primaryLLMClient == nil {
		slog.Error("Failed to create primary LLM client")
		return
	}

	metricsRegistry := prometheus.NewRegistry()
	llmCache := util.NewStringMapCache[string]("LLM prompt cache", cfg.AI.CacheExpirationTime)
	llmMetrics := llm.CreateLLMMetrics(metricsRegistry)
	primaryManager := llm.NewLLMManager(primaryLLMClient, llmCache, llmMetrics, cfg.AI.PrimaryLLM.LLMCompletionTimeout, cfg.AI.PrimaryLLM.LLMConcurrentRequests, true, cfg.AI.PrimaryLLM.PromptPrefix, cfg.AI.PrimaryLLM.PromptSuffix)

	shc := shell.NewShellClient(primaryManager, dbc)

	fakeRequest := models.Request{
		ID:        42,
		SessionID: 42,
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()

		fmt.Printf("Running command: %s\n", line)
		output, err := shc.RunCommand(&fakeRequest, line)
		if err != nil {
			slog.Error("error running command", slog.String("command", line), slog.String("error", err.Error()))
		} else {
			fmt.Printf("%s\n\nUSER=%s\nCWD=%s\nHOSTNAME=%s\n", output.Output, output.EnvUser, output.EnvCWD, output.EnvHostname)
		}
	}
}
