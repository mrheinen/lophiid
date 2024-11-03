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
// This is a helper utility that can be used to extract all resource links from
// a target web page. This is particularly useful when creating a new app and
// content from an existing web page. In that case you point this tool to the
// page you want to serve in the honeypot. The tool will list all resource links
// which you can use with the api client to import those resources.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"lophiid/pkg/html"
	"net/http"
	"os"
	"time"

	"log/slog"
)

var logLevel = flag.String("v", "debug", "Loglevel (debug, info, warn, error)")
var targetURL = flag.String("url", "", "The URL to download")
var timeout = flag.Duration("timeout", 2*time.Minute, "HTTP request timeout")

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

	insecureHttpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := http.Client{
		Transport: insecureHttpTransport,
		Timeout:   *timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest(http.MethodGet, *targetURL, nil)
	if err != nil {
		slog.Error("unable to create http request", slog.String("error", err.Error()))
		return
	}

	res, err := httpClient.Do(req)
	if err != nil {
		slog.Error("unable to fetch", slog.String("error", err.Error()))
		return
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		slog.Error("unable to read body", slog.String("error", err.Error()))
		return
	}

	links := html.ExtractResourceLinks(*targetURL, string(resBody))
	for _, link := range links {
		fmt.Printf("%s\n", link)
	}

}
