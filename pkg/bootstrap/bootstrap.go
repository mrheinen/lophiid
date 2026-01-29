package bootstrap

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"lophiid/pkg/util"
	"os"

	"github.com/kkyr/fig"
)

var (
	// ConfigFile is the shared flag for configuration file path
	ConfigFile = flag.String("c", "", "Config file path")
)

// InitConfig configures the initialization parameters
type InitConfig struct {
	// LogFileExtractor extracts the log file path from the config
	LogFileExtractor func(cfg any) string
	// LogLevelExtractor extracts the log level from the config
	LogLevelExtractor func(cfg any) string
}

// Initialize performs common startup tasks: flag parsing, config loading, and logger setup.
// It returns a cleanup function that should be deferred by the caller.
func Initialize(cfg any, initCfg InitConfig) (func(), error) {
	if !flag.Parsed() {
		flag.Parse()
	}

	var opts []fig.Option
	if *ConfigFile != "" {
		if _, err := os.Stat(*ConfigFile); err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("config file not found: %s", *ConfigFile)
			}
			return nil, fmt.Errorf("error accessing config file: %w", err)
		}

		dir, file := util.SplitFilepath(*ConfigFile)
		opts = append(opts, fig.File(file), fig.Dirs(dir))
	}

	if err := fig.Load(cfg, opts...); err != nil {
		return nil, fmt.Errorf("could not parse config: %w", err)
	}

	logFile := initCfg.LogFileExtractor(cfg)
	logLevel := initCfg.LogLevelExtractor(cfg)

	// Use daily rotating log writer
	lf, err := util.NewDailyRotatingLogWriter(logFile)
	if err != nil {
		return nil, fmt.Errorf("could not open logfile: %w", err)
	}

	// Create tee writer to both stdout and file
	teeWriter := util.NewTeeLogWriter([]io.Writer{os.Stdout, lf})

	var programLevel = new(slog.LevelVar)
	h := slog.NewTextHandler(teeWriter, &slog.HandlerOptions{Level: programLevel})
	slog.SetDefault(slog.New(h))

	switch logLevel {
	case "info":
		programLevel.Set(slog.LevelInfo)
	case "warn":
		programLevel.Set(slog.LevelWarn)
	case "debug":
		programLevel.Set(slog.LevelDebug)
	case "error":
		programLevel.Set(slog.LevelError)
	default:
		slog.Info("Unknown log level given, defaulting to info", "level", logLevel)
		programLevel.Set(slog.LevelInfo)
	}

	return func() {
		lf.Close()
	}, nil
}
