package api

import (
	"encoding/json"
	"fmt"
	"loophid/pkg/database"
	"net/http"
	"strconv"
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

func (a *ApiServer) HandleUpsertSingleContentRule(w http.ResponseWriter, req *http.Request) {
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
	contentId := req.Form.Get("content_id")
	path := req.Form.Get("path")
	pathMatching := req.Form.Get("path_matching")
	body := req.Form.Get("body")
	bodyMatching := req.Form.Get("body_matching")
	method := req.Form.Get("method")

	// We allow the 'content' parameter to be empty to simulate empty replies.
	if contentId == "" || path == "" {
		res.Status = "NOK"
		res.Message = "Empty parameters given"
		json.NewEncoder(w).Encode(res)
		return
	}

	icontentId, err := strconv.ParseInt(contentId, 10, 64)
	if err != nil {
		res.Status = "NOK"
		res.Message = fmt.Sprintf("Unable to parse Content ID %s: %s", contentId, err.Error())
		json.NewEncoder(w).Encode(res)
		return
	}

	if id == "" {
		// This is an insert
		nid, err := a.dbc.InsertContentRule(icontentId, path, pathMatching, method, body, bodyMatching)
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

		err = a.dbc.UpdateContentRule(intID, icontentId, path, pathMatching, method, body, bodyMatching)
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

func (a *ApiServer) HandleGetSingleContentRule(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	id := req.URL.Query().Get("id")
	intID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cr, err := a.dbc.GetContentRuleByID(intID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(cr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *ApiServer) HandleGetAllContentRules(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	crs, err := a.dbc.GetContentRules()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(crs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *ApiServer) HandleUpsertSingleContent(w http.ResponseWriter, req *http.Request) {
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

func (a *ApiServer) HandleGetSingleContent(w http.ResponseWriter, req *http.Request) {
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(cts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *ApiServer) HandleGetAllContent(w http.ResponseWriter, req *http.Request) {
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
