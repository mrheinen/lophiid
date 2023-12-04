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

type HttpContentResult struct {
	Status   string             `json:"status"`
	Message  string             `json:"message"`
	Contents []database.Content `json:"contents"`
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

func (a *ApiServer) HandleUpsertSingleContentRule(w http.ResponseWriter, req *http.Request) {
	var rb database.ContentRule
	rb.ID = 0

	d := json.NewDecoder(req.Body)
	d.DisallowUnknownFields()

	if err := d.Decode(&rb); err != nil {
		json.NewEncoder(w).Encode(HttpContentRuleResult{
			Status:  ResultError,
			Message: err.Error(),
		})
		return
	}

	fmt.Printf("%v\n\n", rb)

	if rb.ContentID == 0 || rb.Path == "" {
		json.NewEncoder(w).Encode(HttpContentRuleResult{
			Status:  ResultError,
			Message: "Empty parameters given",
		})
		return
	}

	if rb.ID == 0 {
		// This is an insert
		//nid, err := a.dbc.InsertContentRule(rb.ContentID, rb.Path, rb.PathMatching, rb.Method, rb.Body, rb.BodyMatching)
		nid, err := a.dbc.InsertContentRule(&rb)
		if err != nil {
			json.NewEncoder(w).Encode(HttpContentRuleResult{
				Status:  ResultError,
				Message: fmt.Sprintf("Unable to update %d: %s", nid, err.Error()),
			})
			return
		}

		json.NewEncoder(w).Encode(HttpContentRuleResult{
			Status:  ResultSuccess,
			Message: fmt.Sprintf("Added new rule (id: %d)", nid),
		})
		return
	} else {

		// This is an update.
		err := a.dbc.UpdateContentRule(&rb)
		if err != nil {
			json.NewEncoder(w).Encode(HttpContentRuleResult{
				Status:  ResultError,
				Message: err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(HttpContentRuleResult{
			Status:  ResultSuccess,
			Message: "Updated rule",
		})
		return
	}
}

func (a *ApiServer) HandleGetSingleContentRule(w http.ResponseWriter, req *http.Request) {
	id := req.URL.Query().Get("id")
	intID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		json.NewEncoder(w).Encode(HttpContentRuleResult{
			Status:  ResultError,
			Message: err.Error(),
		})
		return
	}

	cr, err := a.dbc.GetContentRuleByID(intID)
	if err != nil {
		json.NewEncoder(w).Encode(HttpContentRuleResult{
			Status:  ResultError,
			Message: err.Error(),
		})
		return
	}

	err = json.NewEncoder(w).Encode(HttpContentRuleResult{
		Status:       ResultSuccess,
		ContentRules: []database.ContentRule{cr},
	})

	if err != nil {
		json.NewEncoder(w).Encode(HttpContentRuleResult{
			Status:  ResultError,
			Message: err.Error(),
		})
	}
}

func (a *ApiServer) HandleGetAllContentRules(w http.ResponseWriter, req *http.Request) {
	crs, err := a.dbc.GetContentRules()
	if err != nil {
		json.NewEncoder(w).Encode(HttpContentRuleResult{
			Status:  ResultError,
			Message: err.Error(),
		})
		return
	}

	if err = json.NewEncoder(w).Encode(HttpContentRuleResult{
		Status:       ResultSuccess,
		ContentRules: crs,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *ApiServer) HandleDeleteContentRule(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		json.NewEncoder(w).Encode(HttpContentResult{
			Status:  ResultError,
			Message: err.Error(),
		})
		return
	}
	id := req.Form.Get("id")
	intID, err := strconv.ParseInt(id, 10, 64)

	if err != nil {
		json.NewEncoder(w).Encode(HttpContentRuleResult{
			Status:  ResultError,
			Message: err.Error(),
		})
		return
	}

	err = a.dbc.DeleteContentRule(intID)
	if err != nil {
		json.NewEncoder(w).Encode(HttpContentRuleResult{
			Status:  ResultError,
			Message: err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(HttpContentRuleResult{
		Status:  ResultSuccess,
		Message: fmt.Sprintf("Deleted rule with ID: %s", id),
	})
}

func (a *ApiServer) HandleUpsertSingleContent(w http.ResponseWriter, req *http.Request) {
	var rb database.Content
	rb.ID = 0

	d := json.NewDecoder(req.Body)
	d.DisallowUnknownFields()

	if err := d.Decode(&rb); err != nil {
		json.NewEncoder(w).Encode(HttpContentResult{
			Status:  ResultError,
			Message: err.Error(),
		})
		return
	}

	fmt.Printf("%v\n\n", rb)

	// We allow the 'content' parameter to be empty to simulate empty replies.
	if rb.Name == "" || rb.ContentType == "" || rb.Server == "" {
		json.NewEncoder(w).Encode(HttpContentResult{
			Status:  ResultError,
			Message: "Empty parameters given.",
		})
		return
	}

	if rb.ID == 0 {
		// This is an insert
		nid, err := a.dbc.InsertContent(&rb)
		if err != nil {
			json.NewEncoder(w).Encode(HttpContentResult{
				Status:  ResultError,
				Message: fmt.Sprintf("Unable to update %d: %s", nid, err.Error()),
			})
			return
		}

		json.NewEncoder(w).Encode(HttpContentResult{
			Status:  ResultSuccess,
			Message: fmt.Sprintf("Added new content (id: %d)", nid),
		})
		return
	} else {

		err := a.dbc.UpdateContent(&rb)
		if err != nil {
			json.NewEncoder(w).Encode(HttpContentResult{
				Status:  ResultError,
				Message: err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(HttpContentResult{
			Status:  ResultSuccess,
			Message: "Updated content",
		})
		return
	}
}

func (a *ApiServer) HandleGetSingleContent(w http.ResponseWriter, req *http.Request) {
	id := req.URL.Query().Get("id")
	intID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		json.NewEncoder(w).Encode(HttpContentResult{
			Status:  ResultError,
			Message: err.Error(),
		})
		return
	}

	cts, err := a.dbc.GetContentByID(intID)
	if err != nil {
		json.NewEncoder(w).Encode(HttpContentResult{
			Status:  ResultError,
			Message: err.Error(),
		})
		return
	}

	ret := HttpContentResult{
		Status: ResultSuccess,
		Contents: []database.Content{
			cts,
		},
	}
	json.NewEncoder(w).Encode(ret)
}

func (a *ApiServer) HandleGetAllContent(w http.ResponseWriter, req *http.Request) {
	cts, err := a.dbc.GetContent()
	if err != nil {
		json.NewEncoder(w).Encode(HttpContentResult{
			Status:  ResultError,
			Message: err.Error(),
		})
	}

	json.NewEncoder(w).Encode(HttpContentResult{
		Status:   ResultSuccess,
		Contents: cts,
	})
}

func (a *ApiServer) HandleDeleteContent(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		json.NewEncoder(w).Encode(HttpContentResult{
			Status:  ResultError,
			Message: err.Error(),
		})
		return
	}
	id := req.Form.Get("id")
	intID, err := strconv.ParseInt(id, 10, 64)

	if err != nil {
		json.NewEncoder(w).Encode(HttpContentResult{
			Status:  ResultError,
			Message: err.Error(),
		})
		return
	}

	err = a.dbc.DeleteContent(intID)
	if err != nil {
		json.NewEncoder(w).Encode(HttpContentResult{
			Status:  ResultError,
			Message: err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(HttpContentResult{
		Status:  ResultSuccess,
		Message: fmt.Sprintf("Deleted Content with ID: %s", id),
	})
}

func (a *ApiServer) HandleGetAllRequests(w http.ResponseWriter, req *http.Request) {
	reqs, err := a.dbc.GetRequests()
	if err != nil {
		json.NewEncoder(w).Encode(HttpRequestsResult{
			Status:  ResultError,
			Message: err.Error(),
		})
		return
	}

	if err = json.NewEncoder(w).Encode(HttpRequestsResult{
		Status:   ResultSuccess,
		Requests: reqs,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
