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
package cli

import (
	"fmt"
	"io"
	"log/slog"
	"lophiid/pkg/api"
	"lophiid/pkg/database"
	"lophiid/pkg/util"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"

type ApiCLI struct {
	httpClient     *http.Client
	contentAPI     api.ApiClient[database.Content]
	appAPI         api.ApiClient[database.Application]
	contentRuleAPI api.ApiClient[database.ContentRule]
}

func NewApiCLI(httpClient *http.Client, contentAPI *api.GenericApiClient[database.Content], appAPI *api.GenericApiClient[database.Application], contentRuleAPI *api.GenericApiClient[database.ContentRule]) *ApiCLI {
	return &ApiCLI{
		httpClient:     httpClient,
		appAPI:         appAPI,
		contentAPI:     contentAPI,
		contentRuleAPI: contentRuleAPI,
	}
}

// FetchUrlAndCreateContentAndRuleFromFile will read URLs from a file and will
// then fetch each URL and create Content and ContentRules for them.
func (a *ApiCLI) FetchUrlAndCreateContentAndRuleFromFile(appID int64, ports []int64, targetUrlFile string) error {
	content, err := util.ReadFileToString(targetUrlFile)
	if err != nil {
		return fmt.Errorf("while reading from file: %s. %w", targetUrlFile, err)
	}

	for _, url := range strings.Split(content, "\n") {
		if !strings.HasPrefix(url, "http") {
			slog.Warn("Malformed URL. Skipping", slog.String("url", url))
			continue
		}

		if err := a.FetchUrlAndCreateContentAndRule(appID, ports, url); err != nil {
			return fmt.Errorf("while fetching url: %s. %w", url, err)
		}
	}

	return nil
}

func (a *ApiCLI) FetchUrlAndCreateContentAndRule(appID int64, ports []int64, targetUrl string) error {
	// Check if the app actually exists.
	apps, err := a.appAPI.GetDatamodelSegment(fmt.Sprintf("id:%d", appID), 0, 10)
	if err != nil {
		return fmt.Errorf("error fetching app: %w", err)
	}

	if len(apps) != 1 {
		return fmt.Errorf("could not find app with ID: %d", appID)
	}

	// Download the URL and create the content.
	content, err := a.FetchUrlToContent(apps[0].Name, targetUrl)
	if err != nil {
		return fmt.Errorf("error fetching url to content: %w", err)
	}

	return a.CreateContentAndRule(&apps[0], ports, &content, targetUrl)
}

// CreateContentAndRule will store the Content and a newly created ContentRule
// in the database.
func (a *ApiCLI) CreateContentAndRule(app *database.Application, ports []int64, content *database.Content, targetUrl string) error {
	addedContent, err := a.contentAPI.UpsertDataModel(*content)
	if err != nil {
		return fmt.Errorf("error storing content: %w", err)
	}

	pUrl, _ := url.Parse(targetUrl)

	pathQuery := pUrl.Path
	if pathQuery == "" {
		pathQuery = "/"
	}

	if pUrl.RawQuery != "" {
		pathQuery = fmt.Sprintf("%s?%s", pathQuery, pUrl.RawQuery)
	}

	for _, port := range ports {
		// Store the content rule.
		newContentRule := database.ContentRule{
			ContentID:        addedContent.ID,
			Method:           http.MethodGet,
			Uri:              pathQuery,
			UriMatching:      "exact",
			BodyMatching:     "none",
			AppID:            app.ID,
			Port:             port,
			RequestPurpose:   "UNKNOWN",
			Responder:        "NONE",
			ResponderDecoder: "NONE",
			Enabled:          true,
		}

		addedContentRule, err := a.contentRuleAPI.UpsertDataModel(newContentRule)
		if err != nil {
			return fmt.Errorf("error storing content rule: %w", err)
		}

		slog.Info("added content and rule", slog.Int64("content_id", addedContent.ID), slog.Int64("rule_id", addedContentRule.ID), slog.Int64("port", addedContentRule.Port))
	}
	return nil
}

// FetchUrlToContent will fetch a URL and will save the data as a Content in
// lophiid. It will preserve important headers so that, when the content is
// served by a honeypot, it will look like the real deal.
func (a *ApiCLI) FetchUrlToContent(namePrefix string, targetUrl string) (database.Content, error) {

	// These headers contain values that are likely expired when serving them in
	// the future. We therefore ignore them.
	headersToIgnore := map[string]bool{
		"expires": true,
		"date":    true,
	}

	retContent := database.Content{}

	slog.Info("fetching url", slog.String("url", targetUrl))
	req, _ := http.NewRequest(http.MethodGet, targetUrl, nil)
	req.Header.Add("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("User-Agent", UserAgent)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return retContent, fmt.Errorf("error fetching url: %w", err)
	}

	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return retContent, fmt.Errorf("error reading response: %w", err)
	}

	retContent.Data = respBytes
	retContent.StatusCode = fmt.Sprintf("%d", resp.StatusCode)
	retContent.Description = fmt.Sprintf("Fetched from URL: %s", targetUrl)
	retContent.Name = fmt.Sprintf("%s - %s", namePrefix, req.URL.Path)

	for name, value := range resp.Header {
		if strings.ToLower(name) == "server" {
			retContent.Server = value[0]
			continue
		}

		if strings.ToLower(name) == "content-type" {
			retContent.ContentType = value[0]
			continue
		}

		if _, ok := headersToIgnore[strings.ToLower(name)]; ok {
			continue
		}

		// Maybe this is a wrong assumption but it seems very unlikely that we
		// receive the same header multiple times but with different values. We do
		// not support this (yet).
		retContent.Headers = append(retContent.Headers, fmt.Sprintf("%s: %s", name, value[0]))
	}

	if retContent.Server == "" {
		retContent.Server = "Apache"
	}

	if retContent.ContentType == "" {
		retContent.ContentType = "text/plain"
	}
	return retContent, nil
}

func (a *ApiCLI) ImportApp(appFile string) error {
	data, err := os.ReadFile(appFile)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	err = a.appAPI.Import(string(data))
	if err != nil {
		return fmt.Errorf("error importing app: %w", err)
	}

	return nil
}
