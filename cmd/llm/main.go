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
	"flag"
	"fmt"
	"lophiid/pkg/backend/responder"
	"lophiid/pkg/llm"
	"lophiid/pkg/util"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var apiKey = flag.String("api-key", "", "The OpenAPI API key")
var apiLocation = flag.String("api-location", "http://localhost:8000/v1", "The OpenAPI API location")
var timeoutSec = flag.Int("api-timeout_sec", 20, "API request timeout seconds")
var maxInputLength = flag.Int("m", 10000, "Max input length")
var query = flag.String("p", "", "The prompt input to send")
var responderType = flag.String("t", "COMMAND_INJECTION", "The responder type (e.g. COMMAND_INJECTION, SOURCE_CODE_EXECUTION)")

func main() {

	flag.Parse()
	if *apiKey == "" || *query == "" {
		fmt.Printf("Usage: %s -api-key <api-key> -p <prompt> [-t <responder-type>]\n", os.Args[0])
		return
	}
	metricsRegistry := prometheus.NewRegistry()
	llmClient := llm.NewOpenAILLMClient(*apiKey, *apiLocation, "")

	pCache := util.NewStringMapCache[string]("LLM prompt cache", time.Hour)
	llmMetrics := llm.CreateLLMMetrics(metricsRegistry)
	llmManager := llm.NewLLMManager(llmClient, pCache, llmMetrics, time.Second*time.Duration(*timeoutSec))
	llmResponder := responder.NewLLMResponder(llmManager, *maxInputLength)
	res, err := llmResponder.Respond(*responderType, *query, responder.LLMReplacementTag)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Output: \n\n%s\n", res)
}
