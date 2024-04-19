package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"loophid/pkg/database"
	"net/http"
	"net/url"
	"strings"
)

type GenericHttpResult[T any] struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Data    []T    `json:"data"`
}

type GenericApiClient[T any] struct {
	httpClient  *http.Client
	apiLocation string
	apiKey      string
}

func NewApplicationApiClient(httpClient *http.Client, apiLocation string, apiKey string) *GenericApiClient[database.Application] {
	return &GenericApiClient[database.Application]{
		httpClient:  httpClient,
		apiLocation: apiLocation,
		apiKey:      apiKey,
	}
}

func NewContentApiClient(httpClient *http.Client, apiLocation string, apiKey string) *GenericApiClient[database.Content] {
	return &GenericApiClient[database.Content]{
		httpClient:  httpClient,
		apiLocation: apiLocation,
		apiKey:      apiKey,
	}
}

func NewContentRuleApiClient(httpClient *http.Client, apiLocation string, apiKey string) *GenericApiClient[database.ContentRule] {
	return &GenericApiClient[database.ContentRule]{
		httpClient:  httpClient,
		apiLocation: apiLocation,
		apiKey:      apiKey,
	}
}

// GetDatamodelSegment uses the API to search instances of T.  The query can be
// left an empty string in which case all instanes are returned (within offset
// and limit).
func (a *GenericApiClient[T]) GetDatamodelSegment(query string, offset, limit int) ([]T, error) {
	retApp := []T{}
	apiUrl := fmt.Sprintf("%s/segment?q=%s&offset=%d&limit=%d", a.apiLocation,url.QueryEscape(query),offset, limit)
	slog.Debug("Fetching URL", slog.String("url", apiUrl))
	req, _ := http.NewRequest(http.MethodGet, apiUrl, nil)
	req.Header.Add("accept", "application/json")
	req.Header.Add("API-Key", a.apiKey)

	res, err := a.httpClient.Do(req)
	if err != nil {
		return retApp, fmt.Errorf("while fetching: %s", err)
	}

	defer res.Body.Close()

	d := json.NewDecoder(res.Body)
	d.DisallowUnknownFields()

	var httpRes GenericHttpResult[T]
	if err := d.Decode(&httpRes); err != nil {
		return retApp, err
	}

	if httpRes.Status == ResultError {
		return retApp, fmt.Errorf("got error from API: %s", httpRes.Message)
	}

	return httpRes.Data, nil
}

// UpsertDataModel uses the API to upsert T.  If T has an ID then the API will
// try to update the existing model. If the ID is missing then a new model is
// inserted.
func (a *GenericApiClient[T]) UpsertDataModel(dm T) (T, error) {
	var ret T
	appJson, err := json.Marshal(dm)
	if err != nil {
		return ret, fmt.Errorf("unable to marshal: %w", err)
	}

	payload := bytes.NewReader(appJson)

	apiUrl := fmt.Sprintf("%s/upsert", a.apiLocation)

	req, _ := http.NewRequest(http.MethodPost, apiUrl, payload)
	req.Header.Add("accept", "application/json")
	req.Header.Add("API-Key", a.apiKey)

	res, err := a.httpClient.Do(req)
	if err != nil {
		return ret, fmt.Errorf("while submitting: %s", err)
	}

	defer res.Body.Close()

	d := json.NewDecoder(res.Body)
	d.DisallowUnknownFields()

	var httpRes GenericHttpResult[T]
	if err := d.Decode(&httpRes); err != nil {
		return ret, fmt.Errorf("when decoding: %w", err)
	}

	if httpRes.Data == nil || len(httpRes.Data) != 1 {
		return ret, fmt.Errorf("unexpected data returned by api: %+v", httpRes)
	}
	return httpRes.Data[0], nil
}

// DeleteDataModel will delete the datamodel of type T and ID modelId.
func (a *GenericApiClient[T]) DeleteDataModel(modelId int64) error {
	form := url.Values{}
	form.Add("id", fmt.Sprintf("%d", modelId))

	apiUrl := fmt.Sprintf("%s/delete", a.apiLocation)

	req, _ := http.NewRequest(http.MethodPost, apiUrl, strings.NewReader(form.Encode()))
	req.Header.Add("accept", "application/json")
	req.Header.Add("API-Key", a.apiKey)

	res, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("while deleting: %s", err)
	}

	defer res.Body.Close()
	d := json.NewDecoder(res.Body)
	d.DisallowUnknownFields()

	var httpRes GenericHttpResult[T]
	if err := d.Decode(&httpRes); err != nil {
		return fmt.Errorf("when decoding: %w", err)
	}

	if httpRes.Data == nil || len(httpRes.Data) != 1 {
		return fmt.Errorf("unexpected data returned by api: %+v", httpRes)
	}

	if httpRes.Status != ResultSuccess {
		return fmt.Errorf("could not delete: %s", httpRes.Message)
	}
	return nil
}
