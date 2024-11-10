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
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"lophiid/pkg/database/models"
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

type ApiClient[T any] interface {
	GetDatamodelSegment(query string, offset, limit int) ([]T, error)
	UpsertDataModel(dm T) (T, error)
	DeleteDataModel(modelId int64) error
	Import(data string) error
}

type FakeApiClient[T any] struct {
	DataModelToReturn T
	ErrorToReturn     error
	LastModelStored   T
}

func (f *FakeApiClient[T]) GetDatamodelSegment(query string, offset, limit int) ([]T, error) {
	return []T{f.DataModelToReturn}, f.ErrorToReturn
}

func (f *FakeApiClient[T]) UpsertDataModel(dm T) (T, error) {
	f.LastModelStored = dm
	return f.DataModelToReturn, f.ErrorToReturn
}

func (f *FakeApiClient[T]) DeleteDataModel(modelId int64) error {
	return f.ErrorToReturn
}

func (f *FakeApiClient[T]) Import(data string) error {
	return f.ErrorToReturn
}

// NewApplicationApiClient creates an application api client
func NewApplicationApiClient(httpClient *http.Client, apiLocation string, apiKey string) *GenericApiClient[models.Application] {
	return &GenericApiClient[models.Application]{
		httpClient:  httpClient,
		apiLocation: apiLocation,
		apiKey:      apiKey,
	}
}

// NewContentApiClient creates a content api client
func NewContentApiClient(httpClient *http.Client, apiLocation string, apiKey string) *GenericApiClient[models.Content] {
	return &GenericApiClient[models.Content]{
		httpClient:  httpClient,
		apiLocation: apiLocation,
		apiKey:      apiKey,
	}
}

// NewContentRuleApiClient creates a content rule api client
func NewContentRuleApiClient(httpClient *http.Client, apiLocation string, apiKey string) *GenericApiClient[models.ContentRule] {
	return &GenericApiClient[models.ContentRule]{
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
	apiUrl := fmt.Sprintf("%s/segment?q=%s&offset=%d&limit=%d", a.apiLocation, url.QueryEscape(query), offset, limit)
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

func (a *GenericApiClient[T]) Import(data string) error {
	payload := bytes.NewReader([]byte(data))

	// Right now only the application API allows importing.
	var check T
	switch any(check).(type) {
	case models.Application:
		slog.Debug("Importing application")
	default:
		return fmt.Errorf("api does not support import: %s", a.apiLocation)
	}

	apiUrl := fmt.Sprintf("%s/import", a.apiLocation)

	req, _ := http.NewRequest(http.MethodPost, apiUrl, payload)
	req.Header.Add("accept", "application/json")
	req.Header.Add("API-Key", a.apiKey)

	res, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("while submitting: %s", err)
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("got HTTP error code: %d", res.StatusCode)
	}

	defer res.Body.Close()

	d := json.NewDecoder(res.Body)
	d.DisallowUnknownFields()

	var httpRes GenericHttpResult[T]
	if err := d.Decode(&httpRes); err != nil {
		return fmt.Errorf("when decoding: %w", err)
	}

	if httpRes.Status != ResultSuccess {
		return fmt.Errorf("api call failed: %+v", httpRes)
	}
	return nil
}
