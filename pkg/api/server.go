// Lophiid distributed honeypot
// Copyright (C) 2025 Niels Heinen
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
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"lophiid/backend_service"
	"lophiid/pkg/backend/extractors"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/javascript"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"lophiid/pkg/util/templator"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

type ApiServer struct {
	dbc         database.DatabaseClient
	jRunner     javascript.JavascriptRunner
	globalStats *GlobalStatisticsResult
	statsMutex  sync.Mutex
	statsChan   chan bool
	apiKey      string
}

type HttpResult struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

// For testing
type HttpContentResult struct {
	Status  string           `json:"status"`
	Message string           `json:"message"`
	Data    []models.Content `json:"data"`
}

// For testing
type HttpContentRuleResult struct {
	Status  string               `json:"status"`
	Message string               `json:"message"`
	Data    []models.ContentRule `json:"data"`
}

const ResultSuccess = "OK"
const ResultError = "ERR"

// StoredQueryJSON is a representation of models.StoredQuery but able to be
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
		dbc:       dbc,
		jRunner:   jRunner,
		apiKey:    apiKey,
		statsChan: make(chan bool),
	}
}

// Start starts the API server and will start a background routine that will
// update the global statistics at a fixed interval.
func (a *ApiServer) Start() {

	statsTicker := time.NewTicker(time.Minute * 60)
	go func() {

		globalStats, _ := GetGlobalStatistics(a.dbc)
		a.globalStats = &globalStats

		for {
			select {
			case <-a.statsChan:
				statsTicker.Stop()
				return
			case <-statsTicker.C:
				newGlobalStats, err := GetGlobalStatistics(a.dbc)
				if err != nil {
					slog.Error("failed to get global stats", "error", err)
				}

				a.statsMutex.Lock()
				a.globalStats = &newGlobalStats
				a.statsMutex.Unlock()
			}
		}
	}()

}

func (a *ApiServer) Stop() {
	a.statsChan <- true
}

// Auth middleware will compare the clients API key with the one that was used
// to create the API server instance.
func (a *ApiServer) AuthMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("API-Key")

		if subtle.ConstantTimeCompare([]byte(key), []byte(a.apiKey)) != 1 {
			slog.Error("Did not get a valid API key. ")
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

func (a *ApiServer) HandleGetGlobalStatistics(w http.ResponseWriter, req *http.Request) {
	a.statsMutex.Lock()
	defer a.statsMutex.Unlock()
	if a.globalStats == nil {
		a.sendStatus(w, "Stats not loaded yet, please refresh in a minute", ResultError, nil)
		return
	}

	a.sendStatus(w, "", ResultSuccess, a.globalStats)
}

func (a *ApiServer) HandleUpsertSingleContentRule(w http.ResponseWriter, req *http.Request) {
	var rb models.ContentRule
	rb.ID = 0

	d := json.NewDecoder(req.Body)
	d.DisallowUnknownFields()

	if err := d.Decode(&rb); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	if rb.ContentID == 0 || rb.AppID == 0 || (rb.Uri == "" && rb.Body == "") {
		a.sendStatus(w, "Empty parameters given", ResultError, nil)
		return
	}

	for _, p := range rb.Ports {
		if p < 0 || p > 65535 {
			a.sendStatus(w, fmt.Sprintf("Invalid port number %d: must be between 0 and 65535", p), ResultError, nil)
			return
		}
	}

	// If we have no reference to the content UUID yet, fetch the content and take
	// the UUID from it.
	if rb.ContentUuid == "" {
		content, err := a.dbc.GetContentByID(rb.ContentID)
		if err != nil {
			a.sendStatus(w, err.Error(), ResultError, nil)
			return
		}

		rb.ContentUuid = content.ExtUuid
	}

	if rb.ResponderRegex != "" {
		_, err := regexp.Compile(rb.ResponderRegex)
		if err != nil {
			a.sendStatus(w, "responder regex did not compile", ResultError, nil)
			return
		}
	}

	// If we have no reference to the app UUID yet, do the same.
	if rb.AppUuid == "" {
		app, err := a.dbc.GetAppByID(rb.AppID)
		if err != nil {
			a.sendStatus(w, err.Error(), ResultError, nil)
		}

		rb.AppUuid = app.ExtUuid
	}

	currentTags, err := a.dbc.SearchTagPerRule(0, 200, fmt.Sprintf("rule_id:%d", rb.ID))
	if err != nil {
		a.sendStatus(w, fmt.Sprintf("unable to query tags: %s", err.Error()), ResultError, nil)
		return
	}

	existingTagsMap := make(map[int64]models.TagPerRule)
	submittedTagsMap := make(map[int64]bool)
	for _, t := range currentTags {
		existingTagsMap[t.TagID] = t
	}

	// Check which tags to add.
	for _, t := range rb.TagsToApply {
		submittedTagsMap[t.TagID] = true
		if _, ok := existingTagsMap[t.TagID]; !ok {
			_, err := a.dbc.Insert(&models.TagPerRule{
				TagID:  t.TagID,
				RuleID: rb.ID,
			})

			if err != nil {
				slog.Warn("Could not add rule tag", slog.String("error", err.Error()))
			}
		}
	}

	// Check which tags to remove.
	for k, v := range existingTagsMap {
		if _, ok := submittedTagsMap[k]; !ok {
			err := a.dbc.Delete(&v)
			if err != nil {
				slog.Warn("Could not delete rule tag", slog.String("error", err.Error()))
			}
		}
	}

	if rb.ID == 0 {
		dm, err := a.dbc.InsertExternalModel(&rb)
		if err != nil {
			errMsg := fmt.Sprintf("unable to update %d: %s", dm.ModelID(), err.Error())
			a.sendStatus(w, errMsg, ResultError, nil)
			return
		}

		a.sendStatus(w, fmt.Sprintf("Added new rule (id: %d)", dm.ModelID()), ResultSuccess, []models.DataModel{dm})
		return
	} else {

		// This is an update.
		err := a.dbc.Update(&rb)
		if err != nil {
			a.sendStatus(w, err.Error(), ResultError, nil)
			return
		}

		a.sendStatus(w, "Updated rule", ResultSuccess, []models.DataModel{&rb})
		return
	}
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

	err = a.dbc.Delete(&models.ContentRule{ID: intID})
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	a.sendStatus(w, fmt.Sprintf("Deleted rule with ID: %s", id), ResultSuccess, nil)
}

func RenderTemplate(content models.Content) ([]byte, error) {
	templr := templator.NewTemplator()
	newData, err := templr.RenderTemplate(&models.Request{}, content.Data)
	if err != nil {
		return content.Data, fmt.Errorf("error rendering template: %s", err.Error())
	}

	return newData, nil
}

func CalculateContentLength(content models.Content, renderedData []byte) error {
	cLen := len(renderedData)

	// Check if there is a content length.
	for _, header := range content.Headers {
		headerParts := strings.SplitN(header, ": ", 2)
		if len(headerParts) != 2 {
			return fmt.Errorf("invalid header: %s", header)
		}

		if strings.EqualFold(headerParts[0], "content-length") {
			hLen, err := strconv.Atoi(headerParts[1])
			if err != nil {
				return fmt.Errorf("invalid content length: %s", headerParts[1])
			}

			if hLen != cLen {
				return fmt.Errorf("content-length should be: %d", cLen)
			}
		}
	}

	return nil
}

func (a *ApiServer) HandleUpsertSingleContent(w http.ResponseWriter, req *http.Request) {
	var rb models.Content
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

	renderedData, err := RenderTemplate(rb)
	if err != nil {
		a.sendStatus(w, fmt.Sprintf("template error: %s", err.Error()), ResultError, nil)
		return
	}

	if err := CalculateContentLength(rb, renderedData); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
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
		modifiedScript := fmt.Sprintf("%s\n__validate();", rb.Script)
		eCol := extractors.NewExtractorCollection(true)
		err := a.jRunner.RunScript(modifiedScript, models.Request{
			ID:            42,
			Port:          80,
			Uri:           "/foo",
			Host:          "localhost",
			Path:          "/foo",
			Referer:       "http://localhost",
			ContentLength: 42,
			UserAgent:     "wget",
			Body:          []byte("this is body"),
		}, &backend_service.HttpResponse{}, eCol, true)

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
		dm, err := a.dbc.InsertExternalModel(&rb)
		if err != nil {
			a.sendStatus(w, fmt.Sprintf("unable to insert %d: %s", dm.ModelID(), err.Error()), ResultError, nil)
			return
		}

		a.sendStatus(w, fmt.Sprintf("Added new content (id: %d)", dm.ModelID()), ResultSuccess, []models.DataModel{dm})
		return
	} else {

		err := a.dbc.Update(&rb)
		if err != nil {
			a.sendStatus(w, fmt.Sprintf("unable to update content: %s", err.Error()), ResultError, nil)
			return
		}

		a.sendStatus(w, "Updated content", ResultSuccess, []models.DataModel{&rb})
		return
	}
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

	err = a.dbc.Delete(&models.Content{ID: intID})
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
		a.sendStatus(w, "No result", ResultSuccess, nil)
		return
	}

	res[0].RdapString = string(res[0].Rdap)
	a.sendStatus(w, "", ResultSuccess, res[0])
}

func (a *ApiServer) HandleGetYaraForDownload(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	id := req.Form.Get("id")

	// Only return 25 maximum matches which would already be excessive.
	res, err := a.dbc.SearchYara(0, 25, fmt.Sprintf("download_id:%s", id))
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	if len(res) == 0 {
		a.sendStatus(w, "No result", ResultSuccess, nil)
		return
	}

	a.sendStatus(w, "", ResultSuccess, res)
}

func (a *ApiServer) HandleGetDescriptionForCmpHash(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	hash := req.Form.Get("cmp_hash")
	res, err := a.dbc.SearchRequestDescription(0, 1, fmt.Sprintf("cmp_hash:%s", hash))
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	if len(res) == 0 {
		a.sendStatus(w, "No result", ResultSuccess, nil)
		return
	}

	a.sendStatus(w, "", ResultSuccess, res[0])
}

func (a *ApiServer) HandleDescriptionReview(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	validStatus := map[string]bool{
		constants.DescriberReviewedOk:  true,
		constants.DescriberReviewedNok: true,
		constants.DescriberUnreviewed:  true,
	}

	status := req.Form.Get("status")
	hash := req.Form.Get("hash")

	if _, ok := validStatus[status]; !ok {
		a.sendStatus(w, "Invalid status", ResultError, nil)
		return
	}

	res, err := a.dbc.SearchRequestDescription(0, 1, fmt.Sprintf("cmp_hash:%s", hash))
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	if len(res) == 0 {
		a.sendStatus(w, "No result", ResultSuccess, nil)
		return
	}

	res[0].ReviewStatus = status

	if err := a.dbc.Update(&res[0]); err != nil {
		a.sendStatus(w, "No result", ResultSuccess, nil)
		return
	}

	a.sendStatus(w, "", ResultSuccess, res[0])
}

func (a *ApiServer) HandleUpsertSingleApp(w http.ResponseWriter, req *http.Request) {
	var rb models.Application
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
		dm, err := a.dbc.InsertExternalModel(&rb)
		if err != nil {
			a.sendStatus(w, fmt.Sprintf("unable to insert %d: %s", dm.ModelID(), err.Error()), ResultError, nil)
			return
		}

		a.sendStatus(w, fmt.Sprintf("Added new app (id: %d)", dm.ModelID()), ResultSuccess, []models.DataModel{dm})
		return
	} else {

		err := a.dbc.Update(&rb)
		if err != nil {
			a.sendStatus(w, fmt.Sprintf("unable to update app: %s", err.Error()), ResultError, nil)
			return
		}

		a.sendStatus(w, "Updated app", ResultSuccess, []models.DataModel{&rb})
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

	err = a.dbc.Delete(&models.Application{ID: intID})
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

	err = a.dbc.Delete(&models.Tag{ID: intID, Name: name})
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	a.sendStatus(w, fmt.Sprintf("Deleted tag with ID: %s, Name: %s", id, name), ResultSuccess, nil)
}

func (a *ApiServer) HandleUpdateRequest(w http.ResponseWriter, req *http.Request) {
	var rb models.Request

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
	var rb models.Honeypot

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
	var rb models.Tag
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

		a.sendStatus(w, fmt.Sprintf("Added new tag (id: %d)", dm.ModelID()), ResultSuccess, []models.DataModel{dm})
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

func (a *ApiServer) HandleUpdateSingleDownload(w http.ResponseWriter, req *http.Request) {
	var rb models.Download

	d := json.NewDecoder(req.Body)
	d.DisallowUnknownFields()

	if err := d.Decode(&rb); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	err := a.dbc.Update(&rb)
	if err != nil {
		a.sendStatus(w, fmt.Sprintf("unable to update download: %s", err.Error()), ResultError, nil)
		return
	}

	a.sendStatus(w, "Updated download", ResultSuccess, nil)
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

	err = a.dbc.Delete(&models.StoredQuery{ID: intID})
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	a.sendStatus(w, fmt.Sprintf("Deleted StoredQuery with ID: %s", id), ResultSuccess, nil)
}

func (a *ApiServer) HandleUpsertStoredQuery(w http.ResponseWriter, req *http.Request) {
	var qj models.StoredQuery

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

	existingTagsMap := make(map[int64]models.TagPerQuery)
	submittedTagsMap := make(map[int64]bool)
	for _, t := range currentTags {
		existingTagsMap[t.TagID] = t
	}

	// Check which tags to add.
	for _, t := range qj.TagsToApply {
		submittedTagsMap[t.TagID] = true
		if _, ok := existingTagsMap[t.TagID]; !ok {
			_, err := a.dbc.Insert(&models.TagPerQuery{
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
	var reqs []models.Request
	query := req.URL.Query().Get("q")
	reqs, err = a.dbc.SearchRequests(iOffset, iLimit, query)

	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}
	a.sendStatus(w, "", ResultSuccess, reqs)
}

func (a *ApiServer) HandleSearchYara(w http.ResponseWriter, req *http.Request) {
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
	var rls []models.Yara
	query := req.URL.Query().Get("q")
	rls, err = a.dbc.SearchYara(iOffset, iLimit, query)

	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}
	a.sendStatus(w, "", ResultSuccess, rls)
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
	var rls []models.ContentRule
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
	var rls []models.Content
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
	var rls []models.IpEvent
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
	var rls []models.Download
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
	var rls []models.Honeypot
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
	var qs []models.StoredQuery
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
	var rls []models.Tag
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
	var rls []models.Application
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
	App      *models.Application  `json:"app"`
	Rules    []models.ContentRule `json:"rules"`
	Contents []models.Content     `json:"contents"`
}

type AppYamlExport struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Vendor  string `json:"vendor"`
	Yaml    string `json:"yaml"`
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

	if app.ExtUuid == "" {
		app.ExtUuid = uuid.NewString()
	}

	ret := AppExport{App: &app}

	// Some rules can refer to the same content. Make sure we get a unique list of
	// contents.
	cIdMap := make(map[int64]bool)
	for _, rule := range rules {
		cIdMap[rule.ContentID] = true
	}

	cIdUuidMap := make(map[int64]string)

	for contentId := range cIdMap {
		content, err := a.dbc.GetContentByID(contentId)
		if err != nil {
			a.sendStatus(w, fmt.Sprintf("getting content by ID: %s", err.Error()), ResultError, nil)
			return
		}

		if content.ExtUuid == "" {
			content.ExtUuid = uuid.NewString()
		}

		cIdUuidMap[content.ID] = content.ExtUuid
		ret.Contents = append(ret.Contents, content)
	}

	for _, rule := range rules {
		rule.AppUuid = app.ExtUuid

		// These are guaranteed to be in the map.
		rule.ContentUuid = cIdUuidMap[rule.ContentID]

		if rule.ExtUuid == "" {
			rule.ExtUuid = uuid.NewString()
		}
		ret.Rules = append(ret.Rules, rule)
	}

	yamlData, err := yaml.Marshal(ret)
	if err != nil {
		a.sendStatus(w, fmt.Sprintf("yaml conversion error: %s", err.Error()), ResultError, nil)
		return
	}

	a.sendStatus(w, "", ResultSuccess, AppYamlExport{
		Yaml:    string(yamlData),
		Name:    ret.App.Name,
		Version: ret.App.Version,
		Vendor:  ret.App.Vendor,
	})
}

// ImportAppWithContentAndRule imports the given app with its rules and contents
// into the database. Everything is imported as new. It also deletes all old apps,
// rules and contents that are linked through eachother via the app uuid. It
// effectively is a replace operation.
func (a *ApiServer) ImportAppWithContentAndRule(w http.ResponseWriter, req *http.Request) {
	var ae AppExport

	body, err := io.ReadAll(req.Body)
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	if err = yaml.Unmarshal(body, &ae); err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	// Collect all existing app(s), rule(s) and content(s) because after the
	// import we will delete the old data from this app (if any).

	if !util.IsValidUUID(ae.App.ExtUuid) {
		a.sendStatus(w, "App UUID is not valid", ResultError, nil)
		return
	}

	existingApps, err := a.dbc.SearchApps(0, 1, fmt.Sprintf("ext_uuid:%s", ae.App.ExtUuid))
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	existingRules, err := a.dbc.SearchContentRules(0, 254, fmt.Sprintf("app_uuid:%s", ae.App.ExtUuid))
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	existingContent := []models.Content{}
	for _, rule := range existingRules {

		if !util.IsValidUUID(rule.ContentUuid) {
			a.sendStatus(w, "Content UUID is not valid", ResultError, nil)
			return
		}

		cts, err := a.dbc.SearchContent(0, 1, fmt.Sprintf("ext_uuid:%s", rule.ContentUuid))
		if err != nil {
			a.sendStatus(w, err.Error(), ResultError, nil)
			return
		}

		if len(cts) != 1 {
			slog.Warn("did not find content for rule", slog.String("content_uuid", rule.ContentUuid), slog.String("rule_uuid", rule.ExtUuid))
			// We warn but proceed. Perhaps the content was deleted manually.
		} else {
			existingContent = append(existingContent, cts[0])
		}
	}

	// Set the app ID to 0 so that it gets inserted as new.
	ae.App.ID = 0
	appModel, err := a.dbc.Insert(ae.App)
	if err != nil {
		a.sendStatus(w, err.Error(), ResultError, nil)
		return
	}

	cm := make(map[string]models.Content)
	for _, cnt := range ae.Contents {
		cm[cnt.ExtUuid] = cnt
	}

	for _, rule := range ae.Rules {

		if !util.IsValidUUID(rule.ContentUuid) {
			a.sendStatus(w, "rule ContentUUID is not valid", ResultError, nil)
			return
		}

		ct, ok := cm[rule.ContentUuid]
		if !ok {
			a.sendStatus(w, "a content is missing", ResultError, nil)
			return
		}

		ct.ID = 0

		if !util.IsValidUUID(rule.ExtUuid) {
			a.sendStatus(w, "rule UUID is not valid", ResultError, nil)
			return
		}

		contentModel, err := a.dbc.Insert(&ct)
		if err != nil {
			a.sendStatus(w, err.Error(), ResultError, nil)
			return
		}

		rule.ID = 0
		rule.ContentID = contentModel.ModelID()
		rule.AppID = appModel.ModelID()
		rule.AppUuid = appModel.(*models.Application).ExtUuid
		rule.ContentUuid = contentModel.(*models.Content).ExtUuid
		_, err = a.dbc.Insert(&rule)
		if err != nil {
			a.sendStatus(w, err.Error(), ResultError, nil)
			return
		}
	}

	for _, rule := range existingRules {
		if err := a.dbc.Delete(&rule); err != nil {
			slog.Error("error deleting rule", slog.String("error", err.Error()))
		}
	}

	for _, cont := range existingContent {
		if err := a.dbc.Delete(&cont); err != nil {
			slog.Error("error deleting content", slog.String("error", err.Error()))
		}
	}

	for _, app := range existingApps {
		if err := a.dbc.Delete(&app); err != nil {
			slog.Error("error deleting app", slog.String("error", err.Error()))
		}
	}

	a.sendStatus(w, "", ResultSuccess, nil)
}

func (a *ApiServer) HandleReturnDocField(w http.ResponseWriter, req *http.Request) {
	modelName := strings.ToLower(req.URL.Query().Get("model"))
	var retval map[string]database.FieldDocEntry

	modelMap := map[string]interface{}{
		"content":     models.Content{},
		"request":     models.Request{},
		"contentrule": models.ContentRule{},
		"application": models.Application{},
		"honeypot":    models.Honeypot{},
		"download":    models.Download{},
		"tag":         models.Tag{},
		"storedquery": models.StoredQuery{},
		"ipevent":     models.IpEvent{},
		"yara":        models.Yara{},
	}

	if model, ok := modelMap[modelName]; ok {
		retval = database.GetDatamodelDocumentationMap(model)
	} else {
		a.sendStatus(w, "Unknown model", ResultError, nil)
	}

	a.sendStatus(w, "", ResultSuccess, retval)
}
