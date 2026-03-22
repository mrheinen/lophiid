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
package campaign

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"lophiid/pkg/llm"
	"lophiid/pkg/util/constants"
)

// Summarizer is an interface for LLM-based campaign summarization.
type Summarizer interface {
	// Summarize takes the aggregation state JSON and returns name, summary, severity.
	Summarize(ctx context.Context, aggregationStateJSON json.RawMessage) (name string, summary string, severity string, err error)
}

// NoOpSummarizer is used when --skip-llm is set.
type NoOpSummarizer struct{}

func (s *NoOpSummarizer) Summarize(_ context.Context, _ json.RawMessage) (string, string, string, error) {
	return "", "", "", nil
}

const defaultSummarizePrompt = `You are a cybersecurity analyst. Analyze the following attack campaign data.

Campaign aggregation state:
%s

Produce a campaign name, narrative summary, and severity assessment.

IMPORTANT: The severity field MUST be exactly one of these four values: LOW, MEDIUM, HIGH, CRITICAL.
Do NOT combine values (e.g. "MEDIUM-HIGH" is invalid). If you are uncertain between two severity levels, always pick the lower one.`

// LLMSummarizeResponse is the expected JSON response from the LLM.
type LLMSummarizeResponse struct {
	Name     string `json:"name" jsonschema_description:"A short, descriptive campaign name (max 80 chars). Use the targeted app, vulnerability type, or attacker infrastructure as the key identifier."`
	Summary  string `json:"summary" jsonschema_description:"A 2-4 sentence narrative summary describing: what is being attacked, how (techniques/payloads), from where (geography/ASN), and the scale/timeline."`
	Severity string `json:"severity" jsonschema_description:"Exactly one of: LOW, MEDIUM, HIGH, CRITICAL. Never combine values. When uncertain between two levels, pick the lower one."  jsonschema:"enum=LOW,enum=MEDIUM,enum=HIGH,enum=CRITICAL"`
}

// LLMSummarizer uses an LLM to generate campaign names, summaries, and severity.
type LLMSummarizer struct {
	llmManager     llm.LLMManagerInterface
	promptTemplate string
}

// NewLLMSummarizer creates a new LLMSummarizer with the given LLM manager.
// It configures the LLM to return structured JSON matching LLMSummarizeResponse.
func NewLLMSummarizer(llmManager llm.LLMManagerInterface, promptTemplate string) (*LLMSummarizer, error) {
	if promptTemplate == "" {
		promptTemplate = defaultSummarizePrompt
	}
	if err := llmManager.SetResponseSchemaFromObject(LLMSummarizeResponse{}, "campaign_summary"); err != nil {
		return nil, fmt.Errorf("setting response schema: %w", err)
	}
	return &LLMSummarizer{
		llmManager:     llmManager,
		promptTemplate: promptTemplate,
	}, nil
}

// Summarize sends the aggregation state to the LLM and parses the response.
func (s *LLMSummarizer) Summarize(ctx context.Context, aggregationStateJSON json.RawMessage) (string, string, string, error) {
	prompt := fmt.Sprintf(s.promptTemplate, string(aggregationStateJSON))

	result, err := s.llmManager.Complete(prompt, false)
	if err != nil {
		return "", "", "", fmt.Errorf("LLM completion failed: %w", err)
	}

	// Parse the JSON response.
	name, summary, severity, err := parseLLMResponse(result.Output)
	if err != nil {
		return "", "", "", fmt.Errorf("parsing LLM response: %w", err)
	}

	severity = ValidateCampaignSeverity(severity)

	return name, summary, severity, nil
}

// parseLLMResponse extracts structured fields from the LLM's JSON response.
func parseLLMResponse(response string) (name, summary, severity string, err error) {
	var parsed LLMSummarizeResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(response)), &parsed); err != nil {
		return "", "", "", fmt.Errorf("parsing LLM JSON: %w", err)
	}

	return parsed.Name, parsed.Summary, parsed.Severity, nil
}

// ValidateCampaignSeverity normalizes and validates a severity string against
// the known campaign severity constants. It uppercases the input and returns
// it if valid, otherwise falls back to CampaignSeverityLow.
func ValidateCampaignSeverity(severity string) string {
	severity = strings.ToUpper(strings.TrimSpace(severity))
	switch severity {
	case constants.CampaignSeverityLow, constants.CampaignSeverityMedium, constants.CampaignSeverityHigh, constants.CampaignSeverityCritical:
		return severity
	default:
		if severity != "" {
			slog.Warn("invalid campaign severity, defaulting to LOW", slog.String("severity", severity))
		}
		return constants.CampaignSeverityLow
	}
}
