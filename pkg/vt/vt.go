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
//
package vt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"lophiid/pkg/util"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrQuotaReached = errors.New("rate limited")
)

type VTClientInterface interface {
	Start()
	Stop()
	CheckIP(ip string) (CheckIPResponse, error)
	SubmitURL(url string) (SubmitURLResponse, error)
	SubmitFile(filename string) (AnalysisResponse, error)
	GetFileAnalysis(id string) (FileAnalysisResponse, error)
}

// VTClient is a virustotal client that uses a cache for storing already
// received results.
type VTClient struct {
	apiKey     string
	ipCache    *util.StringMapCache[CheckIPResponse]
	urlCache   *util.StringMapCache[SubmitURLResponse]
	bgChan     chan bool
	httpClient *http.Client
}

func NewVTClient(apikey string, cacheTimeout time.Duration, httpClient *http.Client) *VTClient {
	ic := util.NewStringMapCache[CheckIPResponse]("vt_ip_cache", cacheTimeout)
	uc := util.NewStringMapCache[SubmitURLResponse]("vt_url_cache", cacheTimeout)
	return &VTClient{
		apiKey:     apikey,
		ipCache:    ic,
		urlCache:   uc,
		httpClient: httpClient,
	}
}

// The response for an IP request.
type CheckIPResponse struct {
	Data CheckIPData `json:"data"`
}

type CheckIPData struct {
	Attributes CheckIPAttributes `json:"attributes"`
}

type CheckIPAttributes struct {
	Whois             string        `json:"whois"`
	Country           string        `json:"country"`
	ASN               int           `json:"asn"`
	ASOwner           string        `json:"as_owner"`
	LastAnalysisDate  int64         `json:"last_analysis_date"`
	LastAnalysisStats AnalysisStats `json:"last_analysis_stats"`
}

type AnalysisStats struct {
	Harmless   int64 `json:"harmless"`
	Malicious  int64 `json:"malicious"`
	Suspicious int64 `json:"suspicious"`
	Undetected int64 `json:"undetected"`
	Timeout    int64 `json:"timeout"`
}

// Submit URL data
type SubmitURLResponse struct {
	Data SubmitURLAnalysisData `json:"data"`
}

type SubmitURLAnalysisData struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// The URL analysis response.
type AnalysisResponse struct {
	Data AnalysisData `json:"data"`
}

type AnalysisData struct {
	Type       string             `json:"type"`
	ID         string             `json:"id"`
	Attributes AnalysisAttributes `json:"attributes"`
}

type AnalysisAttributes struct {
	LastAnalysisDate  int64         `json:"last_analysis_date"`
	LastAnalysisStats AnalysisStats `json:"last_analysis_stats"`
}

// The File analysis response.
type FileAnalysisResponse struct {
	Data FileAnalysisData `json:"data"`
}

type FileAnalysisData struct {
	Type       string                 `json:"type"`
	ID         string                 `json:"id"`
	Attributes FileAnalysisAttributes `json:"attributes"`
}

type FileAnalysisAttributes struct {
	Date    int64                   `json:"date"`
	Status  string                  `json:"status"`
	Stats   AnalysisStats           `json:"stats"`
	Results map[string]EngineResult `json:"results"`
}

type EngineResult struct {
	Method     string `json:"method"`
	EngineName string `json:"engine_name"`
	Category   string `json:"category"`
	Result     string `json:"result"`
}

func (v *VTClient) CheckIP(ip string) (CheckIPResponse, error) {
	// First check if we have a cached entry for this IP.
	cacheEntry, err := v.ipCache.Get(ip)
	if err == nil {
		return *cacheEntry, nil
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ip)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", v.apiKey)

	var ret CheckIPResponse
	res, err := v.httpClient.Do(req)
	if err != nil {
		return ret, fmt.Errorf("while fetching: %s", err)
	}

	if res.StatusCode == 204 || res.StatusCode == 429 {
		return ret, ErrQuotaReached
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return ret, fmt.Errorf("cannot read response: %s", err)
	}

	if err = json.Unmarshal(body, &ret); err != nil {
		return ret, fmt.Errorf("while unmarshalling: %s", err)
	}

	v.ipCache.Store(ip, ret)
	return ret, nil
}

func (v *VTClient) SubmitURL(url string) (SubmitURLResponse, error) {
	// First check if we have a cached entry for this URL.
	cacheEntry, err := v.urlCache.Get(url)
	if err == nil {
		return *cacheEntry, nil
	}

	var ret SubmitURLResponse
	vtUrl := "https://www.virustotal.com/api/v3/urls"

	payload := strings.NewReader(fmt.Sprintf("url=%s", url))

	req, _ := http.NewRequest(http.MethodPost, vtUrl, payload)
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", v.apiKey)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	res, err := v.httpClient.Do(req)
	if err != nil {
		return ret, fmt.Errorf("while fetching: %s", err)
	}

	if res.StatusCode == 204 || res.StatusCode == 429 {
		return ret, ErrQuotaReached
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return ret, fmt.Errorf("cannot read response: %s", err)
	}

	if err = json.Unmarshal(body, &ret); err != nil {
		return ret, fmt.Errorf("while unmarshalling: %s", err)
	}

	v.urlCache.Store(url, ret)
	return ret, nil
}

func (v *VTClient) GetURLAnalysis(id string) (AnalysisResponse, error) {
	var ret AnalysisResponse
	vtUrl := fmt.Sprintf("https://www.virustotal.com/api/v3/urls/%s", id)

	req, _ := http.NewRequest(http.MethodGet, vtUrl, nil)
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", v.apiKey)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	res, err := v.httpClient.Do(req)
	if err != nil {
		return ret, fmt.Errorf("while fetching: %s", err)
	}

	if res.StatusCode == 204 || res.StatusCode == 429 {
		return ret, ErrQuotaReached
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return ret, fmt.Errorf("cannot read response: %s", err)
	}

	if err = json.Unmarshal(body, &ret); err != nil {
		return ret, fmt.Errorf("while unmarshalling: %s", err)
	}

	return ret, nil
}

// GetAnalysis returns the Analysis response for a URL or File ID.
func (v *VTClient) GetFileAnalysis(id string) (FileAnalysisResponse, error) {
	var ret FileAnalysisResponse
	vtUrl := fmt.Sprintf("https://www.virustotal.com/api/v3/analyses/%s", id)

	req, _ := http.NewRequest(http.MethodGet, vtUrl, nil)
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", v.apiKey)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	res, err := v.httpClient.Do(req)
	if err != nil {
		return ret, fmt.Errorf("while fetching: %s", err)
	}

	if res.StatusCode == 204 || res.StatusCode == 429 {
		return ret, ErrQuotaReached
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return ret, fmt.Errorf("cannot read response: %s", err)
	}

	if err = json.Unmarshal(body, &ret); err != nil {
		return ret, fmt.Errorf("while unmarshalling: %s", err)
	}

	return ret, nil
}

// SubmitFile send the file for analysis to VirusTotal.
func (v *VTClient) SubmitFile(pathWithFilename string) (AnalysisResponse, error) {
	var ret AnalysisResponse
	vtUrl := "https://www.virustotal.com/api/v3/files"

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	file, err := os.Open(pathWithFilename)
	if err != nil {
		return ret, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	fileWithoutPath := filepath.Base(pathWithFilename)
	fw, err := w.CreateFormFile("file", fileWithoutPath)
	if err != nil {
		return ret, fmt.Errorf("creating file form: %w", err)
	}

	if _, err = io.Copy(fw, file); err != nil {
		return ret, fmt.Errorf("copying file in form: %w", err)
	}

	// Close the multipart writer to finalize the request
	w.Close()

	req, _ := http.NewRequest(http.MethodPost, vtUrl, &buf)
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", v.apiKey)
	req.Header.Add("content-type", w.FormDataContentType())

	res, err := v.httpClient.Do(req)
	if err != nil {
		return ret, fmt.Errorf("while fetching: %s", err)
	}

	if res.StatusCode == 204 || res.StatusCode == 429 {
		return ret, ErrQuotaReached
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return ret, fmt.Errorf("cannot read response: %s", err)
	}

	if err = json.Unmarshal(body, &ret); err != nil {
		return ret, fmt.Errorf("while unmarshalling: %s", err)
	}

	return ret, nil
}

func (v *VTClient) Stop() {
	slog.Info("stopping VT client")
	v.bgChan <- true
}

// Start a go routine that will clean expired entries from the cache every two
// hours.
func (v *VTClient) Start() {
	slog.Info("starting VT client")
	ticker := time.NewTicker(time.Hour * 2)
	go func() {
		for {
			select {
			case <-v.bgChan:
				ticker.Stop()
				slog.Info("VT client stopped")
				return
			case <-ticker.C:
				slog.Debug("Cleaning expired VT cached results (if any)")
				v.ipCache.CleanExpired()
			}
		}
	}()
}
