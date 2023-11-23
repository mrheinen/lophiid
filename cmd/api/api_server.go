package main

import (
	"fmt"
	"loophid/pkg/api"
	"loophid/pkg/database"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {

	dbc := database.PostgresClient{}
	err := dbc.Init("postgres://lo:test@localhost/lophiid")
	if err != nil {
		fmt.Printf("Error opening database: %s", err)
		return
	}

	as := api.NewApiServer(&dbc)
	defer dbc.Close()

	r := mux.NewRouter()
	r.HandleFunc("/content/all", as.HandleGetAllContent).Methods("GET")
	r.HandleFunc("/content/single", as.HandleGetSingleContent).Methods("GET")
	r.HandleFunc("/content/upsert", as.HandleUpsertSingleContent).Methods("POST")

	r.HandleFunc("/contentrule/all", as.HandleGetAllContentRules).Methods("GET")
	r.HandleFunc("/contentrule/single", as.HandleGetSingleContentRule).Methods("GET")
	r.HandleFunc("/contentrule/upsert", as.HandleUpsertSingleContentRule).Methods("POST")

	srv := &http.Server{
		Addr:    ":8088",
		Handler: r,
	}
	srv.ListenAndServe()
}
