package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
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
	Data    any    `json:"data"`
}

type HttpContentRuleResult struct {
	Status       string                 `json:"status"`
	Message      string                 `json:"message"`
	ContentRules []database.ContentRule `json:"content_rules"`
}

type HttpRequestsResult struct {
	Status   string             `json:"status"`
	Message  string             `json:"message"`
	Requests []database.Request `json:"requests"`
}

const ResultSuccess = "OK"
const ResultError = "ERR"

func NewApiServer(dbc database.DatabaseClient) *ApiServer {
	return &ApiServer{
		dbc,
	}
}

func (a *ApiServer) sendStatus(w http.ResponseWriter, msg string, result string, data any) {
	if msg != "" {
		if result == ResultSuccess {
			slog.Debug("status", "msg", msg)
		} else {
			slog.Error("status", "msg", msg)
		}
	}
	if err := json.NewEncoder(w).Encode(HttpResult{
		Status:  result,
		Message: msg,
		Data:    data,
	}); err != nil {
		slog.Error("encoding error", "error", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *ApiServer) HandleUpsertSingleContentRule(w http.ResponseWriter, req *http.Request) {
	var rb database.ContentRule
	rb.ID = 0

	d := json.NewDecoder(req.Body)
	d.DisallowUnknownFields()

	if err := d.Decode(&rb); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	if rb.ContentID == 0 || rb.Path == "" {
		errMsg := "Empty parameters given"
		a.sendStatus(w, errMsg, ResultError, nil)
		return
	}

	if rb.ID == 0 {
		nid, err := a.dbc.Insert(&rb)
		if err != nil {
			errMsg := fmt.Sprintf("Unable to update %d: %s", nid, err.Error())
			a.sendStatus(w, errMsg, ResultError, nil)
			return
		}

		a.sendStatus(w, fmt.Sprintf("Added new rule (id: %d)", nid), ResultSuccess, nil)
		return
	} else {

		// This is an update.
		err := a.dbc.Update(&rb)
		if err != nil {
			a.sendStatus(w, err.Error(), ResultError, nil)
			return
		}

		a.sendStatus(w, "Updated rule", ResultSuccess, nil)
		return
	}
}

func (a *ApiServer) HandleGetSingleContentRule(w http.ResponseWriter, req *http.Request) {
	id := req.URL.Query().Get("id")
	intID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	cr, err := a.dbc.GetContentRuleByID(intID)
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	a.sendStatus(w, "", ResultSuccess, []database.ContentRule{cr})
}

func (a *ApiServer) HandleGetAllContentRules(w http.ResponseWriter, req *http.Request) {
	crs, err := a.dbc.GetContentRules()
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	a.sendStatus(w, "", ResultSuccess, crs)
}

func (a *ApiServer) HandleDeleteContentRule(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}
	id := req.Form.Get("id")
	intID, err := strconv.ParseInt(id, 10, 64)

	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	err = a.dbc.Delete(&database.ContentRule{ID: intID})
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	a.sendStatus(w, fmt.Sprintf("Deleted rule with ID: %s", id), ResultSuccess, nil)
}

func (a *ApiServer) HandleUpsertSingleContent(w http.ResponseWriter, req *http.Request) {
	var rb database.Content
	rb.ID = 0

	d := json.NewDecoder(req.Body)
	d.DisallowUnknownFields()

	if err := d.Decode(&rb); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	// We allow the 'content' parameter to be empty to simulate empty replies.
	if rb.Name == "" || rb.ContentType == "" || rb.Server == "" {
		a.sendStatus(w, "Empty parameters given.", ResultError, nil)
		return
	}

	if rb.ID == 0 {
		// This is an insert
		nid, err := a.dbc.Insert(&rb)
		if err != nil {
			a.sendStatus(w, fmt.Sprintf("Unable to insert %d: %s", nid, err.Error()), ResultError, nil)
			return
		}

		a.sendStatus(w, fmt.Sprintf("Added new content (id: %d)", nid), ResultSuccess, nil)
		return
	} else {

		err := a.dbc.Update(&rb)
		if err != nil {
			a.sendStatus(w, fmt.Sprintf("Unable to update content: %s", err.Error()), ResultError, nil)
			return
		}

		a.sendStatus(w, "Updated content", ResultSuccess, nil)
		return
	}
}

func (a *ApiServer) HandleGetSingleContent(w http.ResponseWriter, req *http.Request) {
	id := req.URL.Query().Get("id")
	intID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	cts, err := a.dbc.GetContentByID(intID)
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	a.sendStatus(w, "", ResultSuccess, []database.Content{cts})
}

func (a *ApiServer) HandleGetAllContent(w http.ResponseWriter, req *http.Request) {
	cts, err := a.dbc.GetContent()
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	a.sendStatus(w, "", ResultSuccess, cts)
}

func (a *ApiServer) HandleDeleteContent(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}
	id := req.Form.Get("id")
	intID, err := strconv.ParseInt(id, 10, 64)

	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	err = a.dbc.Delete(&database.Content{ID: intID})
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	a.sendStatus(w, fmt.Sprintf("Deleted Content with ID: %s", id), ResultSuccess, nil)
}

func (a *ApiServer) HandleGetAllRequests(w http.ResponseWriter, req *http.Request) {
	reqs, err := a.dbc.GetRequests()
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}
	a.sendStatus(w, "", ResultSuccess, reqs)
}

func (a *ApiServer) HandleGetRequestsSegment(w http.ResponseWriter, req *http.Request) {
	offset := req.URL.Query().Get("offset")
	iOffset, err := strconv.ParseInt(offset, 10, 64)
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	limit := req.URL.Query().Get("limit")
	iLimit, err := strconv.ParseInt(limit, 10, 64)
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	reqs, err := a.dbc.GetRequestsSegment(iOffset, iLimit)
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}
	a.sendStatus(w, "", ResultSuccess, reqs)
}
