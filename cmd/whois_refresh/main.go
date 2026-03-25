// Lophiid distributed honeypot
// Copyright (C) 2023-2026 Niels Heinen
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
	"bytes"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"lophiid/pkg/backend"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util"
	"lophiid/pkg/whois"

	"github.com/kkyr/fig"
	"github.com/openrdap/rdap"
	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
)

var (
	configFile = flag.String("config", "backend-config.yaml", "Location of the config file")
	fromDate   = flag.String("from", "", "Start date (inclusive) in YYYY-MM-DD format")
	toDate     = flag.String("to", "", "End date (exclusive) in YYYY-MM-DD format")
	dryRun     = flag.Bool("dry-run", false, "Only print IPs that would be refreshed, do not update")
	delay      = flag.Duration("delay", 500*time.Millisecond, "Delay between RDAP lookups to avoid rate limiting")
)

// ipRow is a helper struct for the DISTINCT source_ip query result.
type ipRow struct {
	SourceIP string `ksql:"source_ip"`
}

func main() {
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if *fromDate == "" || *toDate == "" {
		fmt.Fprintf(os.Stderr, "Error: both -from and -to flags are required\n")
		flag.Usage()
		os.Exit(1)
	}

	if _, err := time.Parse("2006-01-02", *fromDate); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid -from date %q: %v\n", *fromDate, err)
		os.Exit(1)
	}
	if _, err := time.Parse("2006-01-02", *toDate); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid -to date %q: %v\n", *toDate, err)
		os.Exit(1)
	}

	// Load configuration.
	var cfg backend.Config
	if _, err := os.Stat(*configFile); err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Could not find config file: %s\n", *configFile)
		} else {
			fmt.Fprintf(os.Stderr, "Error accessing config file %s: %v\n", *configFile, err)
		}
		os.Exit(1)
	}

	d, f := util.SplitFilepath(*configFile)
	if err := fig.Load(&cfg, fig.File(f), fig.Dirs(d)); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Connect to database.
	db, err := kpgx.New(context.Background(), cfg.Backend.Database.Url, ksql.Config{
		MaxOpenConns: 1,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	dbc := database.NewKSQLClient(&db)

	// Fetch distinct source IPs from the request table in the given date window.
	var ips []ipRow
	_, err = dbc.ParameterizedQuery(
		"SELECT DISTINCT source_ip FROM request WHERE created_at >= $1 AND created_at < $2",
		&ips, *fromDate, *toDate,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error querying distinct IPs: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d unique IPs in request table between %s and %s\n", len(ips), *fromDate, *toDate)

	if *dryRun {
		for _, row := range ips {
			fmt.Println(row.SourceIP)
		}
		return
	}

	// Set up RDAP client.
	rdapClient := &rdap.Client{
		HTTP: &http.Client{Timeout: cfg.WhoisManager.ClientTimeout},
	}

	// Set up GeoIP lookup if enabled.
	var geoIPLookup whois.GeoIPLookup
	if cfg.WhoisManager.GeoIPEnabled {
		gl, err := whois.NewMaxMindGeoIPLookup(cfg.WhoisManager.GeoIPDbDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing GeoIP: %v\n", err)
			os.Exit(1)
		}
		defer gl.Close()
		geoIPLookup = gl
		slog.Info("GeoIP lookup enabled", slog.String("db_dir", cfg.WhoisManager.GeoIPDbDir))
	}

	var updated, inserted, errCount int
	for i, row := range ips {
		ip := row.SourceIP
		slog.Info("Processing IP", slog.String("ip", ip), slog.Int("progress", i+1), slog.Int("total", len(ips)))

		// Perform RDAP lookup.
		resNetwork, err := rdapClient.QueryIP(ip)
		if err != nil {
			slog.Warn("RDAP lookup failed, skipping", slog.String("ip", ip), slog.String("error", err.Error()))
			errCount++
			time.Sleep(*delay)
			continue
		}

		rdapPrinter := rdap.Printer{}
		var printerOutput bytes.Buffer
		rdapPrinter.Writer = &printerOutput
		rdapPrinter.Print(resNetwork)

		// Check if a whois record already exists for this IP.
		existing, err := dbc.SearchWhois(0, 1, fmt.Sprintf("ip:%s", ip))

		if err != nil {
			slog.Error("Failed to query whois records", slog.String("ip", ip), slog.String("error", err.Error()))
			continue

		}
		if len(existing) > 0 {
			// Update the existing record.
			record := existing[0]
			record.Data = ""
			record.Rdap = printerOutput.Bytes()
			record.Country = resNetwork.Country

			if geoIPLookup != nil {
				enrichRecord(geoIPLookup, ip, &record)
			}

			if err := dbc.Update(&record); err != nil {
				slog.Warn("Failed to update whois record", slog.String("ip", ip), slog.String("error", err.Error()))
				errCount++
			} else {
				updated++
			}
		} else {
			// Insert a new record.
			record := models.Whois{
				IP:      ip,
				Data:    "",
				Rdap:    printerOutput.Bytes(),
				Country: resNetwork.Country,
			}

			if geoIPLookup != nil {
				enrichRecord(geoIPLookup, ip, &record)
			}

			if _, err := dbc.Insert(&record); err != nil {
				slog.Warn("Failed to insert whois record", slog.String("ip", ip), slog.String("error", err.Error()))
				errCount++
			} else {
				inserted++
			}
		}

		time.Sleep(*delay)
	}

	fmt.Printf("Done. Updated: %d, Inserted: %d, Errors: %d\n", updated, inserted, errCount)
}

// enrichRecord performs a GeoIP lookup and applies the result to the whois record.
func enrichRecord(lookup whois.GeoIPLookup, ip string, record *models.Whois) {
	result, err := lookup.Lookup(ip)
	if err != nil {
		slog.Warn("GeoIP lookup failed", slog.String("ip", ip), slog.String("error", err.Error()))
		return
	}
	whois.ApplyGeoIPResult(record, result)
}
