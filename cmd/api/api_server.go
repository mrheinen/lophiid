package main

import (
	"context"
	"flag"
	"fmt"
	"loophid/pkg/api"
	"loophid/pkg/database"
	"net/http"
	"os"

	"log/slog"

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

	dbc := database.NewKSQLClient(&db)
	as := api.NewApiServer(dbc)
	defer dbc.Close()

	r := mux.NewRouter()
	// All content endpoints.
	r.HandleFunc("/content/all", as.HandleGetAllContent).Methods("GET")
	r.HandleFunc("/content/single", as.HandleGetSingleContent).Methods("GET")
	r.HandleFunc("/content/upsert", as.HandleUpsertSingleContent).Methods("POST")
	r.HandleFunc("/content/delete", as.HandleDeleteContent).Methods("POST")

	// All rules endpoints.
	r.HandleFunc("/contentrule/all", as.HandleGetAllContentRules).Methods("GET")
	r.HandleFunc("/contentrule/single", as.HandleGetSingleContentRule).Methods("GET")
	r.HandleFunc("/contentrule/upsert", as.HandleUpsertSingleContentRule).Methods("POST")
	r.HandleFunc("/contentrule/delete", as.HandleDeleteContentRule).Methods("POST")

	// All requests endpoints
	r.HandleFunc("/request/all", as.HandleGetAllRequests).Methods("GET")
	r.HandleFunc("/request/segment", as.HandleGetRequestsSegment).Methods("GET")

	handler := cors.Default().Handler(r)

	srv := &http.Server{
		Addr:    ":8088",
		Handler: handler,
	}
	srv.ListenAndServe()
}
