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
	"flag"
	"fmt"
	"io"
	"lophiid/pkg/api"
	"lophiid/pkg/database"
	"lophiid/pkg/javascript"
	"lophiid/pkg/util"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"log/slog"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/kkyr/fig"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/cors"
	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
)

var logLevel = flag.String("v", "debug", "Loglevel (debug, info, warn, error)")

var configFile = flag.String("c", "", "Config file")
var apiKey = flag.String("k", "", "API key to run with")

type Config struct {
	General struct {
		LogFile    string `fig:"log_file" validate:"required"`
		LogLevel   string `fig:"log_level" default:"debug"`
		ListenIP   string `fig:"listen_ip" validate:"required"`
		ListenPort string `fig:"listen_port" validate:"required"`
	} `fig:"general"`
	Cors struct {
		// Comma separated list of allowed origins.
		AllowedOrigins string `fig:"allowed_origins" default:"*"`
	} `fig:"cors"`
	Database struct {
		Url                string `fig:"url" validate:"required"`
		MaxOpenConnections int    `fig:"max_open_connections" default:"10"`
	} `fig:"database" validate:"required"`
	Scripting struct {
		// The allowed commands to run.
		AllowedCommands []string      `fig:"allowed_commands"`
		CommandTimeout  time.Duration `fig:"command_timeout" default:"1m"`
	} `fig:"scripting"`
}

func main() {

	flag.Parse()

	var cfg Config
	if err := fig.Load(&cfg, fig.File(*configFile)); err != nil {
		fmt.Printf("Could not parse config: %s\n", err)
		return
	}

	lf, err := os.OpenFile(cfg.General.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Could not open logfile: %s\n", err)
		return
	}

	defer lf.Close()

	teeWriter := util.NewTeeLogWriter([]io.Writer{os.Stdout, lf})

	var programLevel = new(slog.LevelVar) // Info by default
	h := slog.NewTextHandler(teeWriter, &slog.HandlerOptions{Level: programLevel})
	slog.SetDefault(slog.New(h))

	switch cfg.General.LogLevel {
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

	db, err := kpgx.New(context.Background(), cfg.Database.Url,
		ksql.Config{
			MaxOpenConns: cfg.Database.MaxOpenConnections,
		})
	if err != nil {
		fmt.Printf("Error opening database: %s", err)
		return
	}

	if *apiKey == "" {
		id := uuid.New()
		*apiKey = id.String()
	}

	fmt.Printf("Starting with API key: %s\n", *apiKey)

	reg := prometheus.NewRegistry()
	dbc := database.NewKSQLClient(&db)
	jRunner := javascript.NewGojaJavascriptRunner(dbc, cfg.Scripting.AllowedCommands, cfg.Scripting.CommandTimeout, nil, javascript.CreateGoJaMetrics(reg))
	as := api.NewApiServer(dbc, jRunner, *apiKey)
	as.Start()
	defer as.Stop()
	defer dbc.Close()

	r := mux.NewRouter()
	// All content endpoints.
	r.HandleFunc("/content/upsert", as.HandleUpsertSingleContent).Methods("POST")
	r.HandleFunc("/content/delete", as.HandleDeleteContent).Methods("POST")
	r.HandleFunc("/content/segment", as.HandleSearchContent).Methods("GET")

	// All rules endpoints.
	r.HandleFunc("/contentrule/upsert", as.HandleUpsertSingleContentRule).Methods("POST")
	r.HandleFunc("/contentrule/delete", as.HandleDeleteContentRule).Methods("POST")
	r.HandleFunc("/contentrule/segment", as.HandleSearchContentRules).Methods("GET")

	// All requests endpoints
	r.HandleFunc("/request/update", as.HandleUpdateRequest).Methods("POST")
	r.HandleFunc("/request/segment", as.HandleGetRequestsSegment).Methods("GET")

	r.HandleFunc("/description/single", as.HandleGetDescriptionForCmpHash).Methods("POST")
	r.HandleFunc("/description/status", as.HandleDescriptionReview).Methods("POST")

	// All application endpoints
	r.HandleFunc("/app/upsert", as.HandleUpsertSingleApp).Methods("POST")
	r.HandleFunc("/app/delete", as.HandleDeleteApp).Methods("POST")
	r.HandleFunc("/app/export", as.ExportAppWithContentAndRule).Methods("POST")
	r.HandleFunc("/app/import", as.ImportAppWithContentAndRule).Methods("POST")
	r.HandleFunc("/app/segment", as.HandleSearchApps).Methods("GET")

	r.HandleFunc("/downloads/segment", as.HandleSearchDownloads).Methods("GET")
	r.HandleFunc("/downloads/update", as.HandleUpdateSingleDownload).Methods("POST")

	r.HandleFunc("/meta/request", as.HandleGetMetadataForRequest).Methods("POST")

	r.HandleFunc("/honeypot/update", as.HandleUpdateHoneypot).Methods("POST")
	r.HandleFunc("/honeypot/segment", as.HandleSearchHoneypots).Methods("GET")

	r.HandleFunc("/tag/upsert", as.HandleUpsertSingleTag).Methods("POST")
	r.HandleFunc("/tag/segment", as.HandleSearchTags).Methods("GET")
	r.HandleFunc("/tag/delete", as.HandleDeleteTag).Methods("POST")

	r.HandleFunc("/tagforrequest/get", as.HandleGetTagsForRequestFull).Methods("POST")

	r.HandleFunc("/whois/ip", as.HandleGetWhoisForIP).Methods("POST")

	r.HandleFunc("/storedquery/segment", as.HandleSearchStoredQueries).Methods("GET")
	r.HandleFunc("/storedquery/upsert", as.HandleUpsertStoredQuery).Methods("POST")
	r.HandleFunc("/storedquery/delete", as.HandleDeleteStoredQuery).Methods("POST")

	r.HandleFunc("/datamodel/doc", as.HandleReturnDocField).Methods("GET")

	r.HandleFunc("/events/segment", as.HandleSearchEvents).Methods("GET")

	r.HandleFunc("/yara/bydownloadid", as.HandleGetYaraForDownload).Methods("POST")
	r.HandleFunc("/yara/segment", as.HandleSearchYara).Methods("GET")

	r.HandleFunc("/stats/global", as.HandleGetGlobalStatistics).Methods("GET")

	r.Use(as.AuthMW)

	origins := make([]string, 0)
	for _, o := range strings.Split(cfg.Cors.AllowedOrigins, ",") {
		origins = append(origins, strings.TrimSpace(o))
	}

	c := cors.New(cors.Options{
		AllowedOrigins: origins,
		AllowedHeaders: []string{"API-Key", "Content-Type"},
		AllowedMethods: []string{"GET", "POST"},
		Debug:          false,
	})

	handler := c.Handler(r)

	srv := &http.Server{
		Addr:    net.JoinHostPort(cfg.General.ListenIP, cfg.General.ListenPort),
		Handler: handler,
	}
	srv.ListenAndServe()
}
