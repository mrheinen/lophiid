package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"loophid/pkg/api"
	"loophid/pkg/database"
	"loophid/pkg/javascript"
	"loophid/pkg/util"
	"net"
	"net/http"
	"os"
	"strings"

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

	id := uuid.New()

	fmt.Printf("Starting with API key: %s\n", id.String())

	reg := prometheus.NewRegistry()
	jRunner := javascript.NewGojaJavascriptRunner(javascript.CreateGoJaMetrics(reg))
	dbc := database.NewKSQLClient(&db)
	as := api.NewApiServer(dbc, jRunner, id.String())
	defer dbc.Close()

	r := mux.NewRouter()
	// All content endpoints.
	r.HandleFunc("/content/all", as.HandleGetAllContent).Methods("GET")
	r.HandleFunc("/content/single", as.HandleGetSingleContent).Methods("GET")
	r.HandleFunc("/content/upsert", as.HandleUpsertSingleContent).Methods("POST")
	r.HandleFunc("/content/delete", as.HandleDeleteContent).Methods("POST")
	r.HandleFunc("/content/segment", as.HandleSearchContent).Methods("GET")

	// All rules endpoints.
	r.HandleFunc("/contentrule/all", as.HandleGetAllContentRules).Methods("GET")
	r.HandleFunc("/contentrule/single", as.HandleGetSingleContentRule).Methods("GET")
	r.HandleFunc("/contentrule/upsert", as.HandleUpsertSingleContentRule).Methods("POST")
	r.HandleFunc("/contentrule/delete", as.HandleDeleteContentRule).Methods("POST")
	r.HandleFunc("/contentrule/segment", as.HandleSearchContentRules).Methods("GET")

	// All requests endpoints
	r.HandleFunc("/request/all", as.HandleGetAllRequests).Methods("GET")
	r.HandleFunc("/request/update", as.HandleUpdateRequest).Methods("POST")
	r.HandleFunc("/request/segment", as.HandleGetRequestsSegment).Methods("GET")

	// All application endpoints
	r.HandleFunc("/app/all", as.HandleGetAllApps).Methods("GET")
	r.HandleFunc("/app/upsert", as.HandleUpsertSingleApp).Methods("POST")
	r.HandleFunc("/app/delete", as.HandleDeleteApp).Methods("POST")
	r.HandleFunc("/app/export", as.ExportAppWithContentAndRule).Methods("POST")
	r.HandleFunc("/app/import", as.ImportAppWithContentAndRule).Methods("POST")
	r.HandleFunc("/app/segment", as.HandleSearchApps).Methods("GET")

	r.HandleFunc("/downloads/all", as.HandleGetAllDownloads).Methods("GET")
	r.HandleFunc("/downloads/segment", as.HandleSearchDownloads).Methods("GET")

	r.HandleFunc("/meta/request", as.HandleGetMetadataForRequest).Methods("POST")

	r.HandleFunc("/honeypot/all", as.HandleGetAllHoneypots).Methods("GET")
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
