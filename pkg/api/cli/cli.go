package cli

import (
	"fmt"
	"io"
	"log/slog"
	"loophid/pkg/api"
	"loophid/pkg/database"
	"loophid/pkg/util"
	"net/http"
	"net/url"
	"strings"
)

var UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"

type ApiCLI struct {
	httpClient     *http.Client
	contentAPI     *api.GenericApiClient[database.Content]
	appAPI         *api.GenericApiClient[database.Application]
	contentRuleAPI *api.GenericApiClient[database.ContentRule]
}

func NewApiCLI(httpClient *http.Client, contentAPI *api.GenericApiClient[database.Content], appAPI *api.GenericApiClient[database.Application], contentRuleAPI *api.GenericApiClient[database.ContentRule]) *ApiCLI {
	return &ApiCLI{
		httpClient:     httpClient,
		appAPI:         appAPI,
		contentAPI:     contentAPI,
		contentRuleAPI: contentRuleAPI,
	}
}

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

	appName := apps[0].Name

	// Download the URL and create the content.
	content, err := a.FetchUrlToContent(appName, targetUrl)
	if err != nil {
		return fmt.Errorf("error fetching url to content: %w", err)
	}

	// Store the content.
	addedContent, err := a.contentAPI.UpsertDataModel(content)
	if err != nil {
		return fmt.Errorf("error storing content: %w", err)
	}

	pUrl, _ := url.Parse(targetUrl)

	path := pUrl.Path
	if path == "" {
		path = "/"
	}

	for _, port := range ports {
		// Store the content rule.
		newContentRule := database.ContentRule{
			ContentID:    addedContent.ID,
			Method:       http.MethodGet,
			Uri:          pUrl.Path,
			UriMatching:  "exact",
			BodyMatching: "none",
			AppID:        appID,
			Port:         port,
		}

		addedContentRule, err := a.contentRuleAPI.UpsertDataModel(newContentRule)
		if err != nil {
			return fmt.Errorf("error storing content rule: %w", err)
		}

		slog.Info("added content rule", slog.Int64("rule_id", addedContentRule.ID), slog.Int64("port", addedContentRule.Port))
	}
	return nil
}

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

	return retContent, nil
}
