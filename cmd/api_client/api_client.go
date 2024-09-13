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
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/fs"
	"lophiid/pkg/api"
	"lophiid/pkg/api/cli"
	"lophiid/pkg/database"
	"net/http"
	"os"
	"path/filepath"
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

var appImport = flag.Bool("app-import", false, "Import apps")
var appImportFile = flag.String("app-import-file", "", "Import the given app, rules and content")
var appImportDir = flag.String("app-import-dir", "", "Import the apps, rules and content from this dir")

// Download flags
var appID = flag.Int64("app-id", 0, "The application ID")
var targetURL = flag.String("url", "", "The URL to download")
var targetURLFile = flag.String("url-file", "", "The file with URLs to download")
var ports = flag.String("ports", "0", "The port to limit on. Multiple ports can be separated by comma.")

func GetFilesRecursivelyFromDir(dir string) ([]string, error) {
	var retFiles []string
	err := filepath.WalkDir(dir, func(s string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error accessing path %q: %w", s, err)
		}
		if !d.IsDir() {
			retFiles = append(retFiles, s)
		}
		return nil
	})

	if err != nil {
		return retFiles, fmt.Errorf("error walking directory %q: %w", dir, err)
	}

	return retFiles, nil
}

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

	if *appImport {
		if *appImportFile != "" {
			if err := apiCliClient.ImportApp(*appImportFile); err != nil {
				slog.Error("Cannot import app", slog.String("error", err.Error()))
			}
			slog.Info("Imported app", slog.String("app", *appImportFile))
			return
		} else if *appImportDir != "" {
			files, err := GetFilesRecursivelyFromDir(*appImportDir)
			if err != nil {
				slog.Error("Cannot get files", slog.String("error", err.Error()))
			}

			for _, file := range files {
				if err := apiCliClient.ImportApp(file); err != nil {
					slog.Error("Cannot import app", slog.String("error", err.Error()))
					return
				}

				slog.Info("Imported app", slog.String("app", file))
			}

		} else {
			slog.Warn("Add -app-import-file or -app-import-dir")
			return
		}
	}

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
