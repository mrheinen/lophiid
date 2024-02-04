package main

import (
	"context"
	"flag"
	"fmt"
	"loophid/pkg/api"
	"loophid/pkg/database"
	"loophid/pkg/javascript"
	"net/http"
	"os"

	"log/slog"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
)

var logLevel = flag.String("v", "debug", "Loglevel (debug, info, warn, error)")

func main() {
	var programLevel = new(slog.LevelVar) // Info by default
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: programLevel})
	slog.SetDefault(slog.New(h))

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

	connectString := "postgres://lo:test@localhost/lophiid"
	db, err := kpgx.New(context.Background(), connectString,
		ksql.Config{
			MaxOpenConns: 3,
		})
	if err != nil {
		fmt.Printf("Error opening database: %s", err)
		return
	}

	id := uuid.New()

	fmt.Printf("Starting with API key: %s\n", id.String())

	jRunner := javascript.NewGojaJavascriptRunner()
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

	r.HandleFunc("/whois/ip", as.HandleGetWhoisForIP).Methods("POST")

	r.Use(as.AuthMW)

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedHeaders: []string{"API-Key", "Content-Type"},
		AllowedMethods: []string{"GET", "POST"},
		Debug:          true,
	})

	handler := c.Handler(r)

	srv := &http.Server{
		Addr:    ":8088",
		Handler: handler,
	}
	srv.ListenAndServe()
}
