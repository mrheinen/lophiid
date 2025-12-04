// Lophiid distributed honeypot
// Copyright (C) 2025 Niels Heinen
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

// Package main provides a CLI tool to replay HTTP requests from the database
// to a honeypot using raw TCP sockets.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"lophiid/pkg/backend"
	"lophiid/pkg/database"

	"github.com/kkyr/fig"
	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
)

var (
	configFile  = flag.String("config", "backend-config.yaml", "Location of the config file")
	dbConnStr   = flag.String("db", "", "Database connection string (overrides config)")
	requestID   = flag.Int64("request-id", 0, "ID of the request to replay (required)")
	overrideIP  = flag.String("ip", "", "Override honeypot IP address")
	overridePort = flag.Int64("port", 0, "Override honeypot port")
	timeout     = flag.Duration("timeout", 15*time.Second, "Connection timeout")
	useTLS      = flag.Bool("tls", false, "Use TLS for the connection")
	insecure    = flag.Bool("insecure", true, "Skip TLS certificate verification")
)

func main() {
	flag.Parse()

	if *requestID == 0 {
		fmt.Fprintf(os.Stderr, "Error: -request-id flag is required\n")
		flag.Usage()
		os.Exit(1)
	}

	// Load configuration
	var cfg backend.Config
	if err := fig.Load(&cfg, fig.File(*configFile)); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	dbUrl := cfg.Backend.Database.Url
	if *dbConnStr != "" {
		dbUrl = *dbConnStr
	}

	// Connect to database
	db, err := kpgx.New(context.Background(), dbUrl, ksql.Config{
		MaxOpenConns: 1,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	dbClient := database.NewKSQLClient(&db)

	// Fetch the request from the database
	req, err := dbClient.GetRequestByID(*requestID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching request with ID %d: %v\n", *requestID, err)
		os.Exit(1)
	}

	if len(req.Raw) == 0 {
		fmt.Fprintf(os.Stderr, "Error: Request %d has no raw data\n", *requestID)
		os.Exit(1)
	}

	// Determine target IP and port
	targetIP := req.HoneypotIP
	if *overrideIP != "" {
		targetIP = *overrideIP
	}

	targetPort := req.Port
	if *overridePort != 0 {
		targetPort = *overridePort
	}

	if targetIP == "" {
		fmt.Fprintf(os.Stderr, "Error: No honeypot IP available (use -ip flag to specify)\n")
		os.Exit(1)
	}

	if targetPort == 0 {
		fmt.Fprintf(os.Stderr, "Error: No port available (use -port flag to specify)\n")
		os.Exit(1)
	}

	// Build the address
	address := net.JoinHostPort(targetIP, fmt.Sprintf("%d", targetPort))

	fmt.Fprintf(os.Stderr, "Replaying request %d to %s\n", *requestID, address)
	fmt.Fprintf(os.Stderr, "Raw request size: %d bytes\n", len(req.Raw))
	fmt.Fprintf(os.Stderr, "---\n")

	// Establish connection using raw TCP socket
	var conn net.Conn
	if *useTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: *insecure,
		}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: *timeout}, "tcp", address, tlsConfig)
	} else {
		conn, err = net.DialTimeout("tcp", address, *timeout)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to %s: %v\n", address, err)
		os.Exit(1)
	}
	defer conn.Close()

	// Set read/write deadlines
	if err := conn.SetDeadline(time.Now().Add(*timeout)); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting deadline: %v\n", err)
		os.Exit(1)
	}

	// Send the raw request
	n, err := conn.Write(req.Raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error sending request: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Sent %d bytes\n", n)
	fmt.Fprintf(os.Stderr, "---\n")

	// Read and print the full response
	response, err := io.ReadAll(conn)
	if err != nil {
		// Check if it's a timeout after we've read some data
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() && len(response) > 0 {
			fmt.Fprintf(os.Stderr, "Connection timed out after reading %d bytes\n", len(response))
		} else if err != io.EOF {
			fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
		}
	}

	// Print the raw response to stdout
	fmt.Print(string(response))
}
