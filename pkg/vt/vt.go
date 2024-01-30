package vt

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"loophid/pkg/util"
	"net/http"
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
}

// VTClient is a virustotal client that uses a cache for storing already
// received results.
type VTClient struct {
	apiKey   string
	ipCache  *util.StringMapCache
	urlCache *util.StringMapCache
	bgChan   chan bool
}

func NewVTClient(apikey string, cacheTimeout time.Duration) *VTClient {
	ic := util.NewStringMapCache(cacheTimeout)
	uc := util.NewStringMapCache(cacheTimeout)
	return &VTClient{
		apiKey:   apikey,
		ipCache:  ic,
		urlCache: uc,
	}
}

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
	Harmless   int `json:"harmless"`
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Undetected int `json:"undetected"`
	Timeout    int `json:"timeout"`
}

// Submit URL data
type SubmitURLResponse struct {
	Data URLAnalysisData `json:"data"`
}

type URLAnalysisData struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (v *VTClient) CheckIP(ip string) (CheckIPResponse, error) {
	// First check if we have a cached entry for this IP.
	cacheEntry, err := v.ipCache.Get(ip)
	if err == nil {
		return cacheEntry.(CheckIPResponse), nil
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ip)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", v.apiKey)

	var ret CheckIPResponse
	res, err := http.DefaultClient.Do(req)
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
		return cacheEntry.(SubmitURLResponse), nil
	}

	var ret SubmitURLResponse
	vtUrl := "https://www.virustotal.com/api/v3/urls"

	payload := strings.NewReader(fmt.Sprintf("url=%s", url))

	req, _ := http.NewRequest("POST", vtUrl, payload)
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", v.apiKey)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
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
