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
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"lophiid/backend_service"
	"lophiid/pkg/database"
	"lophiid/pkg/javascript"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ApiServer struct {
	dbc     database.DatabaseClient
	jRunner javascript.JavascriptRunner
	apiKey  string
}

type HttpResult struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

// For testing
type HttpContentResult struct {
	Status  string             `json:"status"`
	Message string             `json:"message"`
	Data    []database.Content `json:"data"`
}

// For testing
type HttpContentRuleResult struct {
	Status  string                 `json:"status"`
	Message string                 `json:"message"`
	Data    []database.ContentRule `json:"data"`
}

const ResultSuccess = "OK"
const ResultError = "ERR"

// StoredQueryJSON is a representation of database.StoredQuery but able to be
// JSON marshalled
type StoredQueryJSON struct {
	ID          int64     `json:"id"`
	Query       string    `json:"query"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	LastRanAt   time.Time `json:"last_ran_at"`
	RecordCount int64     `json:"record_count"`
	TagsToApply []string  `json:"tags_to_apply"`
}

func NewApiServer(dbc database.DatabaseClient, jRunner javascript.JavascriptRunner, apiKey string) *ApiServer {
	return &ApiServer{
		dbc,
		jRunner,
		apiKey,
	}
}

// Auth middleware will compare the clients API key with the one that was used
// to create the API server instance.
func (a *ApiServer) AuthMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("API-Key")

		if key != a.apiKey {
			slog.Error("Did not get a valid API key")
			http.Error(w, "Authentication error", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
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

	if rb.ContentID == 0 || (rb.Uri == "" && rb.Body == "") {
		errMsg := "Empty parameters given"
		a.sendStatus(w, errMsg, ResultError, nil)
		return
	}

	if rb.ID == 0 {
		dm, err := a.dbc.Insert(&rb)
		if err != nil {
			errMsg := fmt.Sprintf("unable to update %d: %s", dm.ModelID(), err.Error())
			a.sendStatus(w, errMsg, ResultError, nil)
			return
		}

		a.sendStatus(w, fmt.Sprintf("Added new rule (id: %d)", dm.ModelID()), ResultSuccess, []database.DataModel{dm})
		return
	} else {

		// This is an update.
		err := a.dbc.Update(&rb)
		if err != nil {
			a.sendStatus(w, err.Error(), ResultError, nil)
			return
		}

		a.sendStatus(w, "Updated rule", ResultSuccess, []database.DataModel{&rb})
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
		a.sendStatus(w, fmt.Sprintf("decode: %s", err.Error()), ResultError, nil)
		return
	}

	if rb.Name == "" || rb.ContentType == "" || rb.Server == "" {
		a.sendStatus(w, "Empty parameters given.", ResultError, nil)
		return
	}

	// If both the content and the script are set, we currently assume something
	// is wrong because the backend will use on of these and not both.
	if len(rb.Data) > 0 && len(rb.Script) > 0 {
		a.sendStatus(w, "Both data and script are set. Choose one.", ResultError, nil)
		return
	}

	if len(rb.Script) > 0 {
		// Try running the script with a fake request. This to see if it compiles
		// and doesn't produce any errors.
		modifiedScript := fmt.Sprintf("%s\ncreateResponse();", rb.Script)
		err := a.jRunner.RunScript(modifiedScript, database.Request{
			ID:            42,
			Port:          80,
			Uri:           "/foo",
			Host:          "localhost",
			Path:          "/foo",
			Referer:       "http://localhost",
			ContentLength: 42,
			UserAgent:     "wget",
			Body:          []byte("this is body"),
		}, &backend_service.HttpResponse{}, true)

		// The script itself may complain because of the fake data we provided in
		// the above request. We therefore ignore it if this happens and really just
		// want to catch runtime errors.
		if err != nil && !errors.Is(err, javascript.ErrScriptComplained) {
			a.sendStatus(w, fmt.Sprintf("Script did not validate: %s", err), ResultError, nil)
			return
		}
	}

	headerNameRegex := regexp.MustCompile("^[a-zA-Z0-9-_]+$")
	if len(rb.Headers) > 0 {
		for _, header := range rb.Headers {
			headerParts := strings.SplitN(header, ": ", 2)
			if len(headerParts) != 2 {
				a.sendStatus(w, fmt.Sprintf("Invalid header: %s", header), ResultError, nil)
				return
			}

			if !headerNameRegex.MatchString(headerParts[0]) {
				a.sendStatus(w, fmt.Sprintf("Invalid header name: %s", headerParts[0]), ResultError, nil)
				return
			}
		}
	}

	if rb.ID == 0 {
		// This is an insert
		dm, err := a.dbc.Insert(&rb)
		if err != nil {
			a.sendStatus(w, fmt.Sprintf("unable to insert %d: %s", dm.ModelID(), err.Error()), ResultError, nil)
			return
		}

		a.sendStatus(w, fmt.Sprintf("Added new content (id: %d)", dm.ModelID()), ResultSuccess, []database.DataModel{dm})
		return
	} else {

		err := a.dbc.Update(&rb)
		if err != nil {
			a.sendStatus(w, fmt.Sprintf("unable to update content: %s", err.Error()), ResultError, nil)
			return
		}

		a.sendStatus(w, "Updated content", ResultSuccess, []database.DataModel{&rb})
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

func (a *ApiServer) HandleGetWhoisForIP(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}
	ip := req.Form.Get("ip")

	res, err := a.dbc.SearchWhois(0, 1, fmt.Sprintf("ip:%s", ip))
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	if len(res) == 0 {
		a.sendStatus(w, "No result", ResultError, nil)
		return
	}

	res[0].RdapString = string(res[0].Rdap)
	a.sendStatus(w, "", ResultSuccess, res[0])
}

func (a *ApiServer) HandleUpsertSingleApp(w http.ResponseWriter, req *http.Request) {
	var rb database.Application
	rb.ID = 0

	d := json.NewDecoder(req.Body)
	d.DisallowUnknownFields()

	if err := d.Decode(&rb); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	if rb.Name == "" || rb.Version == "" {
		a.sendStatus(w, "App name and version are required", ResultError, nil)
		return
	}

	if rb.ID == 0 {
		// This is an insert
		dm, err := a.dbc.Insert(&rb)
		if err != nil {
			a.sendStatus(w, fmt.Sprintf("unable to insert %d: %s", dm.ModelID(), err.Error()), ResultError, nil)
			return
		}

		a.sendStatus(w, fmt.Sprintf("Added new app (id: %d)", dm.ModelID()), ResultSuccess, []database.DataModel{dm})
		return
	} else {

		err := a.dbc.Update(&rb)
		if err != nil {
			a.sendStatus(w, fmt.Sprintf("unable to update app: %s", err.Error()), ResultError, nil)
			return
		}

		a.sendStatus(w, "Updated app", ResultSuccess, []database.DataModel{&rb})
		return
	}
}

func (a *ApiServer) HandleDeleteApp(w http.ResponseWriter, req *http.Request) {
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

	err = a.dbc.Delete(&database.Application{ID: intID})
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	a.sendStatus(w, fmt.Sprintf("Deleted Application with ID: %s", id), ResultSuccess, nil)
}

func (a *ApiServer) HandleDeleteTag(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}
	id := req.Form.Get("id")
	name := req.Form.Get("name")
	intID, err := strconv.ParseInt(id, 10, 64)

	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	err = a.dbc.Delete(&database.Tag{ID: intID, Name: name})
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	a.sendStatus(w, fmt.Sprintf("Deleted tag with ID: %s, Name: %s", id, name), ResultSuccess, nil)
}

func (a *ApiServer) HandleUpdateRequest(w http.ResponseWriter, req *http.Request) {
	var rb database.Request

	d := json.NewDecoder(req.Body)
	d.DisallowUnknownFields()

	if err := d.Decode(&rb); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	err := a.dbc.Update(&rb)
	if err != nil {
		a.sendStatus(w, fmt.Sprintf("unable to update request: %s", err.Error()), ResultError, nil)
		return
	}

	a.sendStatus(w, "Updated request", ResultSuccess, nil)
}

func (a *ApiServer) HandleUpdateHoneypot(w http.ResponseWriter, req *http.Request) {
	var rb database.Honeypot

	d := json.NewDecoder(req.Body)
	d.DisallowUnknownFields()

	if err := d.Decode(&rb); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	err := a.dbc.Update(&rb)
	if err != nil {
		a.sendStatus(w, fmt.Sprintf("unable to update honeypot: %s", err.Error()), ResultError, nil)
		return
	}

	a.sendStatus(w, "Updated honeypot", ResultSuccess, nil)
}

func (a *ApiServer) HandleUpsertSingleTag(w http.ResponseWriter, req *http.Request) {
	var rb database.Tag
	rb.ID = 0

	d := json.NewDecoder(req.Body)
	d.DisallowUnknownFields()

	if err := d.Decode(&rb); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	if rb.Name == "" || rb.ColorHtml == "" {
		a.sendStatus(w, "Name and html color are required", ResultError, nil)
		return
	}

	if rb.ID == 0 {
		// This is an insert
		dm, err := a.dbc.Insert(&rb)
		if err != nil {
			a.sendStatus(w, fmt.Sprintf("unable to insert %d: %s", dm.ModelID(), err.Error()), ResultError, nil)
			return
		}

		a.sendStatus(w, fmt.Sprintf("Added new tag (id: %d)", dm.ModelID()), ResultSuccess, []database.DataModel{dm})
		return
	} else {

		err := a.dbc.Update(&rb)
		if err != nil {
			a.sendStatus(w, fmt.Sprintf("unable to update tag: %s", err.Error()), ResultError, nil)
			return
		}

		a.sendStatus(w, "Updated tag", ResultSuccess, nil)
		return
	}
}

func (a *ApiServer) HandleDeleteStoredQuery(w http.ResponseWriter, req *http.Request) {
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

	err = a.dbc.Delete(&database.StoredQuery{ID: intID})
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	a.sendStatus(w, fmt.Sprintf("Deleted StoredQuery with ID: %s", id), ResultSuccess, nil)
}

func (a *ApiServer) HandleUpsertStoredQuery(w http.ResponseWriter, req *http.Request) {
	var qj database.StoredQuery

	d := json.NewDecoder(req.Body)
	d.DisallowUnknownFields()

	if err := d.Decode(&qj); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	if qj.ID != 0 {
		err := a.dbc.Update(&qj)
		if err != nil {
			a.sendStatus(w, fmt.Sprintf("unable to update stored Query: %s", err.Error()), ResultError, nil)
			return
		}
	} else {
		q, err := a.dbc.Insert(&qj)
		if err != nil {
			a.sendStatus(w, fmt.Sprintf("unable to insert stored Query: %s", err.Error()), ResultError, nil)
			return
		}
		qj.ID = q.ModelID()
	}

	currentTags, err := a.dbc.SearchTagPerQuery(0, 100, fmt.Sprintf("query_id:%d", qj.ID))
	if err != nil {
		a.sendStatus(w, fmt.Sprintf("unable to query tags: %s", err.Error()), ResultError, nil)
		return
	}

	existingTagsMap := make(map[int64]database.TagPerQuery)
	submittedTagsMap := make(map[int64]bool)
	for _, t := range currentTags {
		existingTagsMap[t.TagID] = t
	}

	// Check which tags to add.
	for _, t := range qj.TagsToApply {
		submittedTagsMap[t.TagID] = true
		if _, ok := existingTagsMap[t.TagID]; !ok {
			fmt.Printf("Adding new query tag: %+v\n", t)
			_, err := a.dbc.Insert(&database.TagPerQuery{
				TagID:   t.TagID,
				QueryID: qj.ID,
			})

			if err != nil {
				slog.Warn("Could not add query tag", slog.String("error", err.Error()))
			}
		}
	}

	// Check which tags to remove.
	for k, v := range existingTagsMap {
		if _, ok := submittedTagsMap[k]; !ok {
			fmt.Printf("Removing query tag: %d\n", v.TagID)
			err := a.dbc.Delete(&v)
			if err != nil {
				slog.Warn("Could not delete query tag", slog.String("error", err.Error()))
			}
		}
	}

	a.sendStatus(w, "Saved changes", ResultSuccess, qj)
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
	var reqs []database.Request
	query := req.URL.Query().Get("q")
	reqs, err = a.dbc.SearchRequests(iOffset, iLimit, query)

	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}
	a.sendStatus(w, "", ResultSuccess, reqs)
}

func (a *ApiServer) HandleSearchContentRules(w http.ResponseWriter, req *http.Request) {
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
	var rls []database.ContentRule
	query := req.URL.Query().Get("q")
	rls, err = a.dbc.SearchContentRules(iOffset, iLimit, query)

	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}
	a.sendStatus(w, "", ResultSuccess, rls)
}

func (a *ApiServer) HandleSearchContent(w http.ResponseWriter, req *http.Request) {
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
	var rls []database.Content
	query := req.URL.Query().Get("q")
	rls, err = a.dbc.SearchContent(iOffset, iLimit, query)

	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}
	a.sendStatus(w, "", ResultSuccess, rls)
}

func (a *ApiServer) HandleSearchEvents(w http.ResponseWriter, req *http.Request) {
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
	var rls []database.IpEvent
	query := req.URL.Query().Get("q")
	rls, err = a.dbc.SearchEvents(iOffset, iLimit, query)

	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}
	a.sendStatus(w, "", ResultSuccess, rls)
}

func (a *ApiServer) HandleSearchDownloads(w http.ResponseWriter, req *http.Request) {
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
	var rls []database.Download
	query := req.URL.Query().Get("q")
	rls, err = a.dbc.SearchDownloads(iOffset, iLimit, query)

	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}
	a.sendStatus(w, "", ResultSuccess, rls)
}

func (a *ApiServer) HandleSearchHoneypots(w http.ResponseWriter, req *http.Request) {
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
	var rls []database.Honeypot
	query := req.URL.Query().Get("q")
	rls, err = a.dbc.SearchHoneypots(iOffset, iLimit, query)

	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}
	a.sendStatus(w, "", ResultSuccess, rls)
}

func (a *ApiServer) HandleSearchStoredQueries(w http.ResponseWriter, req *http.Request) {
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
	var qs []database.StoredQuery
	query := req.URL.Query().Get("q")
	qs, err = a.dbc.SearchStoredQuery(iOffset, iLimit, query)
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	a.sendStatus(w, "", ResultSuccess, qs)
}

func (a *ApiServer) HandleSearchTags(w http.ResponseWriter, req *http.Request) {
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
	var rls []database.Tag
	query := req.URL.Query().Get("q")
	rls, err = a.dbc.SearchTags(iOffset, iLimit, query)

	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}
	a.sendStatus(w, "", ResultSuccess, rls)
}

func (a *ApiServer) HandleSearchApps(w http.ResponseWriter, req *http.Request) {
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
	var rls []database.Application
	query := req.URL.Query().Get("q")
	rls, err = a.dbc.SearchApps(iOffset, iLimit, query)

	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}
	a.sendStatus(w, "", ResultSuccess, rls)
}

func (a *ApiServer) HandleGetMetadataForRequest(w http.ResponseWriter, req *http.Request) {
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

	mds, err := a.dbc.GetMetadataByRequestID(intID)
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	a.sendStatus(w, "", ResultSuccess, mds)
}

func (a *ApiServer) HandleGetTagsForRequest(w http.ResponseWriter, req *http.Request) {
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

	mds, err := a.dbc.SearchTagPerRequest(0, 200, fmt.Sprintf("request_id:%d", intID))
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	a.sendStatus(w, "", ResultSuccess, mds)
}

func (a *ApiServer) HandleGetTagsForRequestFull(w http.ResponseWriter, req *http.Request) {
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

	mds, err := a.dbc.GetTagPerRequestFullForRequest(intID)
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	a.sendStatus(w, "", ResultSuccess, mds)
}

type AppExport struct {
	App      *database.Application
	Rules    []database.ContentRule
	Contents []database.Content
}

func (a *ApiServer) ExportAppWithContentAndRule(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		a.sendStatus(w, fmt.Sprintf("parsing form: %s", err.Error()), ResultError, nil)
		return
	}
	id := req.Form.Get("id")
	intID, err := strconv.ParseInt(id, 10, 64)

	if err != nil {
		a.sendStatus(w, fmt.Sprintf("parsing ID: %s: %s", id, err.Error()), ResultError, nil)
		return
	}

	app, err := a.dbc.GetAppByID(intID)
	if err != nil {
		a.sendStatus(w, fmt.Sprintf("getting app: %s", err.Error()), ResultError, nil)
		return
	}

	rules, err := a.dbc.SearchContentRules(0, 250, fmt.Sprintf("app_id:%d", app.ID))
	if err != nil {
		a.sendStatus(w, fmt.Sprintf("searching content rules: %s", err.Error()), ResultError, nil)
		return
	}

	ret := AppExport{
		App:   &app,
		Rules: rules,
	}

	for _, rule := range rules {
		content, err := a.dbc.GetContentByID(rule.ContentID)
		if err != nil {
			a.sendStatus(w, fmt.Sprintf("getting content by ID: %s", err.Error()), ResultError, nil)
			return
		}

		ret.Contents = append(ret.Contents, content)
	}

	a.sendStatus(w, "", ResultSuccess, ret)
}

// ImportAppWithContentAndRule imports the given app with its rules and contents
// into the database. Everything is imported as new.
func (a *ApiServer) ImportAppWithContentAndRule(w http.ResponseWriter, req *http.Request) {
	var ae AppExport
	d := json.NewDecoder(req.Body)
	d.DisallowUnknownFields()

	if err := d.Decode(&ae); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	// Set the app ID to 0 so that it gets inserted as new.
	ae.App.ID = 0
	appModel, err := a.dbc.Insert(ae.App)
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	cm := make(map[int64]database.Content)
	for _, cnt := range ae.Contents {
		cm[cnt.ID] = cnt
	}

	for _, r := range ae.Rules {
		ct, ok := cm[r.ContentID]
		if !ok {
			a.sendStatus(w, "a rule is missing", ResultError, nil)
			return
		}

		ct.ID = 0
		contentModel, err := a.dbc.Insert(&ct)
		if err != nil {
			a.sendStatus(w, err.Error(), ResultError, nil)
			return
		}

		r.ContentID = contentModel.ModelID()
		r.AppID = appModel.ModelID()
		r.ID = 0
		_, err = a.dbc.Insert(&r)
		if err != nil {
			a.sendStatus(w, err.Error(), ResultError, nil)
			return
		}
	}

	a.sendStatus(w, "", ResultSuccess, nil)
}

func (a *ApiServer) HandleReturnDocField(w http.ResponseWriter, req *http.Request) {
	modelName := strings.ToLower(req.URL.Query().Get("model"))
	var retval map[string]database.FieldDocEntry
	switch modelName {
	case "content":
		retval = database.GetDatamodelDocumentationMap(database.Content{})
	case "request":
		retval = database.GetDatamodelDocumentationMap(database.Request{})
	case "contentrule":
		retval = database.GetDatamodelDocumentationMap(database.ContentRule{})
	case "application":
		retval = database.GetDatamodelDocumentationMap(database.Application{})
	case "honeypot":
		retval = database.GetDatamodelDocumentationMap(database.Honeypot{})
	case "download":
		retval = database.GetDatamodelDocumentationMap(database.Download{})
	case "tag":
		retval = database.GetDatamodelDocumentationMap(database.Tag{})
	case "storedquery":
		retval = database.GetDatamodelDocumentationMap(database.StoredQuery{})
	case "ipevent":
		retval = database.GetDatamodelDocumentationMap(database.IpEvent{})
	default:
		a.sendStatus(w, "Unknown model", ResultError, nil)
	}

	a.sendStatus(w, "", ResultSuccess, retval)
}
