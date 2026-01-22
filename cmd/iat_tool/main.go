// Lophiid distributed honeypot
// Copyright (C) 2026 Niels Heinen
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
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"sort"

	"lophiid/pkg/analysis"
	"lophiid/pkg/backend"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util"

	"github.com/kkyr/fig"
	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
)

var (
	configFile = flag.String("config", "backend-config.yaml", "Location of the config file")
	sessionID  = flag.Int64("session", 0, "Session ID to analyze")
)

func main() {
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if *sessionID == 0 {
		fmt.Fprintf(os.Stderr, "Error: -session flag is required\n")
		flag.Usage()
		os.Exit(1)
	}

	// Load configuration
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

	dbUrl := cfg.Backend.Database.Url

	// Connect to database
	db, err := kpgx.New(context.Background(), dbUrl, ksql.Config{
		MaxOpenConns: 1,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	dbc := database.NewKSQLClient(&db)

	// Fetch the session by ID
	var sessions []models.Session
	sessions, err = dbc.SearchSession(0, 1, fmt.Sprintf("id:%d", *sessionID))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching session: %v\n", err)
		os.Exit(1)
	}

	if len(sessions) == 0 {
		fmt.Fprintf(os.Stderr, "Session with ID %d not found\n", *sessionID)
		os.Exit(1)
	}

	session := sessions[0]

	var gaps []float64

	// Check if session has request gaps stored in database
	if len(session.BehaviorFinalGaps) == 0 {
		slog.Info("No behavior gaps stored in database, fetching requests to calculate gaps")

		// Fetch all requests for this session
		var requests []models.Request
		requests, err = dbc.SearchRequests(0, 10000, fmt.Sprintf("session_id:%d", *sessionID))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching requests for session: %v\n", err)
			os.Exit(1)
		}

		if len(requests) < 2 {
			fmt.Fprintf(os.Stderr, "Session has insufficient requests (%d) to calculate gaps\n", len(requests))
			os.Exit(1)
		}

		// Sort requests by TimeReceived
		sort.Slice(requests, func(i, j int) bool {
			return requests[i].TimeReceived.Before(requests[j].TimeReceived)
		})

		// Calculate gaps between consecutive requests
		for i := 1; i < len(requests); i++ {
			gap := requests[i].TimeReceived.Sub(requests[i-1].TimeReceived).Seconds()
			gaps = append(gaps, gap)
		}

		slog.Info("Calculated gaps from requests", slog.Int("request_count", len(requests)), slog.Int("gap_count", len(gaps)))
	} else {
		gaps = session.BehaviorFinalGaps
		slog.Info("Using stored behavior gaps", slog.Int("gap_count", len(gaps)))
	}

	// Calculate behavior profile
	profile, err := analysis.GetSessionBehaviorProfile(gaps)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error calculating behavior profile: %v\n", err)
		os.Exit(1)
	}

	// Print results
	fmt.Printf("Session Behavior Profile\n")
	fmt.Printf("========================\n")
	fmt.Printf("Session ID:       %d\n", session.ID)
	fmt.Printf("Session IP:       %s\n", session.IP)
	fmt.Printf("Started At:       %s\n", session.StartedAt)
	fmt.Printf("Ended At:         %s\n", session.EndedAt)
	fmt.Printf("Active:           %v\n", session.Active)
	fmt.Printf("\n")
	fmt.Printf("Behavior Analysis\n")
	fmt.Printf("-----------------\n")
	fmt.Printf("Overall CV:       %.4f\n", profile.OverallCV)
	fmt.Printf("Has Bursts:       %v\n", profile.HasBursts)
	fmt.Printf("Is Human:         %v\n", profile.IsHuman())
	fmt.Printf("Final Gaps Count: %d\n", len(profile.FinalGaps))
	fmt.Printf("\n")
	fmt.Printf("Interpretation:\n")
	if profile.OverallCV < 0.5 {
		fmt.Printf("  CV < 0.5: Highly Rhythmic (Scripted/Bot)\n")
	} else if profile.OverallCV >= 0.5 && profile.OverallCV <= 1.0 {
		fmt.Printf("  CV ~ 1.0: Random (Sophisticated Bot)\n")
	} else {
		fmt.Printf("  CV > 1.0: Bursty/Chaotic (Likely Human)\n")
	}
	fmt.Printf("\n")
	fmt.Printf("Inter-Arrival Time Gaps (seconds)\n")
	fmt.Printf("---------------------------------\n")
	for i, gap := range profile.FinalGaps {
		fmt.Printf("  Gap %3d: %.6f\n", i+1, gap)
	}
}
