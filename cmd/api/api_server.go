package main

import (
	"encoding/json"
	"fmt"
	"loophid/pkg/database"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

type ApiServer struct {
	dbc database.DatabaseClient
}

type HttpResult struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func NewApiServer(dbc database.DatabaseClient) *ApiServer {
	return &ApiServer{
		dbc,
	}
}

func (a *ApiServer) handleUpsertSingleContent(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	res := HttpResult{}

	if err := req.ParseForm(); err != nil {
		json.NewEncoder(w).Encode(HttpResult{
			Status:  "NOK",
			Message: err.Error(),
		})
		return
	}

	id := req.Form.Get("id")
	name := req.Form.Get("name")
	content := req.Form.Get("content")
	contentType := req.Form.Get("content_type")
	server := req.Form.Get("server")

	// We allow the 'content' parameter to be empty to simulate empty replies.
	if name == "" || contentType == "" || server == "" {
		res.Status = "NOK"
		res.Message = "Empty parameters given"
		json.NewEncoder(w).Encode(res)
		return
	}

	if id == "" {
		// This is an insert
		nid, err := a.dbc.InsertContent(name, content, contentType, server)
		if err != nil {
			res.Status = "NOK"
			res.Message = fmt.Sprintf("Unable to update %d: %s", nid, err.Error())
			json.NewEncoder(w).Encode(res)
			return
		}

		json.NewEncoder(w).Encode(HttpResult{
			Status:  "OK",
			Message: fmt.Sprintf("Added new content (id: %d)", nid),
		})
		return
	} else {

		// This is an update.
		intID, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			res.Status = "NOK"
			res.Message = fmt.Sprintf("Unable to parse ID %s: %s", id, err.Error())
			json.NewEncoder(w).Encode(res)
			return
		}

		fmt.Printf("Calling update with %d %s %s %s %s\n", intID, name, content, contentType, server)
		err = a.dbc.UpdateContent(intID, name, content, contentType, server)
		if err != nil {
			json.NewEncoder(w).Encode(HttpResult{
				Status:  "NOK",
				Message: err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(HttpResult{
			Status:  "OK",
			Message: "Updated content",
		})
		return
	}
}

func (a *ApiServer) handleGetSingleContent(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	id := req.URL.Query().Get("id")
	intID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cts, err := a.dbc.GetContentByID(intID)
	if err != nil {
		fmt.Printf("getting content: %s\n", err)
	}

	json.NewEncoder(w).Encode(cts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *ApiServer) handleGetAllContent(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	cts, err := a.dbc.GetContent()
	if err != nil {
		fmt.Printf("getting content: %s\n", err)
	}

	json.NewEncoder(w).Encode(cts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func main() {

	dbc := database.PostgresClient{}
	err := dbc.Init("postgres://lo:test@localhost/lophiid")
	if err != nil {
		fmt.Printf("Error opening database: %s", err)
		return
	}

	as := NewApiServer(&dbc)
	defer dbc.Close()

	r := mux.NewRouter()
	r.HandleFunc("/content/all", as.handleGetAllContent).Methods("GET")
	r.HandleFunc("/content/single", as.handleGetSingleContent).Methods("GET")
	r.HandleFunc("/content/upsert", as.handleUpsertSingleContent).Methods("POST")

	srv := &http.Server{
		Addr:    ":8088",
		Handler: r,
	}
	srv.ListenAndServe()
}
