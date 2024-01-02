package vt

import (
	"fmt"
	"io"
	"net/http"

	vtapi "github.com/VirusTotal/vt-go"
)

type VTClient struct {
	vc      *vtapi.Client
	urlScan *vtapi.URLScanner
	apiKey  string
}

func NewVTClient(apikey string) *VTClient {
	client := vtapi.NewClient(apikey)
	return &VTClient{
		vc:      client,
		urlScan: client.NewURLScanner(),
		apiKey:  apikey,
	}
}

func (v *VTClient) SendURL(url string) (string, error) {
	analysis, err := v.urlScan.Scan(url)
	if err != nil {
		return "", fmt.Errorf("when scanning url: %s", err)
	}
	return analysis.ID(), nil
}

func (v *VTClient) GetAnalysis(id string) (string, error) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/analyses/%s", id)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", v.apiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("while fetching: %s", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return string(body), nil
}
