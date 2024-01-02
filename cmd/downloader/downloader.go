package main

import (
	"flag"
	"fmt"
	"loophid/pkg/downloader"
	"os"
	"sync"
	"time"

	"log/slog"
)

var logLevel = flag.String("v", "debug", "Loglevel (debug, info, warn, error)")
var downloadDir = flag.String("d", "/tmp", "Download directory")
var downloadUrl = flag.String("u", "", "Download URL")
var requestId = flag.Int64("r", 42, "Request id")
var httpTimeout = flag.Int64("t", 5, "HTTP timeout in minutes")

func main() {
	flag.Parse()
	var programLevel = new(slog.LevelVar) // Info by default
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: programLevel})
	slog.SetDefault(slog.New(h))

	if *downloadUrl == "" {
		slog.Info("Use with -d <download dir> -u <url>")
		return
	}

	switch *logLevel {
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

	var wg sync.WaitGroup
	nd := downloader.NewHTTPDownloader(*downloadDir, time.Minute*time.Duration(*httpTimeout))
	wg.Add(1)
	go func() {
		targetFile, err := nd.PepareTargetFileDir(fmt.Sprintf("%d", *requestId))
		if err != nil {
			slog.Error("could not prepare", slog.String("error", err.Error()))
			return
		}
		if _, _,  err := nd.FromUrl(*requestId, *downloadUrl, targetFile, &wg); err != nil {
			slog.Error("could not fetch", slog.String("error", err.Error()))
		}
	}()

	wg.Wait()
}
