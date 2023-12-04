package main

import (
	"context"
	"fmt"
	"loophid/pkg/api"
	"loophid/pkg/database"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
)

func main() {
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

	handler := cors.Default().Handler(r)

	srv := &http.Server{
		Addr:    ":8088",
		Handler: handler,
	}
	srv.ListenAndServe()
}
