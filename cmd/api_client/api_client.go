package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"loophid/pkg/api"
	"loophid/pkg/api/cli"
	"loophid/pkg/database"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"log/slog"
)

var logLevel = flag.String("v", "debug", "Loglevel (debug, info, warn, error)")
var apiKey = flag.String("api-key", "", "The API key to use")
var apiLocation = flag.String("api-server", "", "The API location")

// Application specific flags.
var appName = flag.String("app-name", "", "The application name")
var appVersion = flag.String("app-version", "", "The application version")
var appVendor = flag.String("app-vendor", "", "The application vendor")
var appOS = flag.String("app-os", "", "The application OS")
var appLink = flag.String("app-link", "", "The application reference link")

// Download flags
var appID = flag.Int64("app-id", 0, "The application ID")
var targetURL = flag.String("url", "", "The URL to download")
var targetURLFile = flag.String("url-file", "", "The file with URLs to download")
var ports = flag.String("ports", "0", "The port to limit on. Multiple ports can be separated by comma.")

func main() {
	flag.Parse()
	var programLevel = new(slog.LevelVar) // Info by default
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: programLevel})
	slog.SetDefault(slog.New(h))

	switch *logLevel {
	case "info":
		programLevel.Set(slog.LevelInfo)
	case "warn":
		programLevel.Set(slog.LevelWarn)
	case "debug":
		programLevel.Set(slog.LevelDebug)
	case "error":
		programLevel.Set(slog.LevelError)
	default:
		fmt.Printf("Unknown log level given. Using info")
		programLevel.Set(slog.LevelInfo)
	}

	if *apiLocation == "" {
		slog.Error("Please specify the API server with -api-server")
		return
	}

	if *apiKey == "" {
		slog.Error("Please specify the API key with -api-key")
		return
	}

	insecureHttpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := http.Client{
		Transport: insecureHttpTransport,
		Timeout:   time.Minute * 2,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	appAPI := api.NewApplicationApiClient(&httpClient, fmt.Sprintf("%s/app", *apiLocation), *apiKey)
	contentAPI := api.NewContentApiClient(&httpClient, fmt.Sprintf("%s/content", *apiLocation), *apiKey)
	contentRuleAPI := api.NewContentRuleApiClient(&httpClient, fmt.Sprintf("%s/contentrule", *apiLocation), *apiKey)

	apiCliClient := cli.NewApiCLI(&httpClient, contentAPI, appAPI, contentRuleAPI)

	if *targetURL != "" || *targetURLFile != "" {
		if *appID == 0 {
			slog.Warn("Please specify the app ID")
			return
		}

		var rulePorts []int64
		for _, port := range strings.Split(*ports, ",") {
			portInt, err := strconv.ParseInt(port, 10, 64)
			if err != nil {
				slog.Warn("Could not parse port", slog.String("port", port))
			}

			rulePorts = append(rulePorts, portInt)
		}

		if *targetURL != "" {
			err := apiCliClient.FetchUrlAndCreateContentAndRule(*appID, rulePorts, *targetURL)
			if err != nil {
				slog.Warn("got error fetching content", slog.String("error", err.Error()))
			}

		} else {
			err := apiCliClient.FetchUrlAndCreateContentAndRuleFromFile(*appID, rulePorts, *targetURLFile)
			if err != nil {
				slog.Warn("got error fetching content", slog.String("error", err.Error()))
			}
		}
	} else if *appName != "" && *appVersion != "" {

		app := database.Application{
			Name:    *appName,
			Version: *appVersion,
			Vendor:  *appVendor,
			Link:    *appLink,
			OS:      *appOS,
		}

		newApp, err := appAPI.UpsertDataModel(app)
		if err != nil {
			slog.Warn("got error creating app", slog.String("error", err.Error()))
			return
		}

		fmt.Printf("Created app with ID: %d\n", newApp.ID)
	}
}
