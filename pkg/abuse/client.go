package abuse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

type AbuseClientInterface interface {
}

type AbuseClient struct {
	httpTimeout time.Duration
	authKey     string
	httpClient  *http.Client
}

// IOCSearchRequest is a struct used to create the JSON request for searching
// IOCs
type IOCSearchRequest struct {
	Query      string `json:"query"`
	SearchTerm string `json:"search_term"`
}

type IOCSearchResponse struct {
	QueryStatus string `json:"query_status"`
	Data        struct {
		ID               string  `json:"id"`
		IOC              string  `json:"ioc"`
		ThreatType       string  `json:"threat_type"`
		ThreatTypeDesc   string  `json:"threat_type_desc"`
		IOCType          string  `json:"ioc_type"`
		IOCTypeDesc      string  `json:"ioc_type_desc"`
		Malware          string  `json:"malware"`
		MalwarePrintable string  `json:"malware_printable"`
		MalwareAlias     string  `json:"malware_alias"`
		MalwareMalpedia  string  `json:"malware_malpedia"`
		ConfidenceLevel  int     `json:"confidence_level"`
		FirstSeen        *string `json:"first_seen"`
		LastSeen         *string `json:"last_seen"`
		Reference        *string `json:"reference"`
		Reporter         string  `json:"reporter"`
	} `json:"data"`
}

const threatFoxApiUrl = "https://threatfox-api.abuse.ch/api/v1/"

func NewAbuseClient(httpClient *http.Client, authKey string, httpTimeout time.Duration) *AbuseClient {
	return &AbuseClient{
		httpTimeout: httpTimeout,
		authKey:     authKey,
		httpClient:  httpClient,
	}
}

func (a *AbuseClient) SearchIOC(searchTerm string) (IOCSearchResponse, error) {
	result := IOCSearchResponse{}
	iocSearchRequest := IOCSearchRequest{
		Query:      "search_ioc",
		SearchTerm: searchTerm,
	}

	requestBody, err := json.Marshal(iocSearchRequest)
	if err != nil {
		slog.Error("failed to marshal request", slog.String("error", err.Error()))
		return result, err
	}

	req, _ := http.NewRequest(http.MethodPost, threatFoxApiUrl, bytes.NewReader(requestBody))
	req.Header.Add("Auth-Key", a.authKey)

	res, err := a.httpClient.Do(req)
	if res.StatusCode != http.StatusOK {
		return result, err
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return result, fmt.Errorf("cannot read response: %s", err)
	}

	if err = json.Unmarshal(body, &result); err != nil {
		return result, fmt.Errorf("while unmarshalling: %s", err)
	}

	return result, nil
}
