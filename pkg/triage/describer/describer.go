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
package describer

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"lophiid/pkg/analysis"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"lophiid/pkg/util/constants"
	"time"
)

type DescriptionManager interface {
	MaybeAddNewHash(hash string, req *models.Request) error
	Start()
}

// CachedDescriptionManager is a manager for request descriptions. It caches
// descriptions in memory so that database calls are minimal.
type CachedDescriptionManager struct {
	dbClient     database.DatabaseClient
	llmManager   *llm.LLMManager
	eventManager analysis.IpEventManager
	metrics      *DescriberMetrics
}

type QueueEntry struct {
	RequestDescription models.RequestDescription
	Request            models.Request
}

type LLMResult struct {
	Description       string `json:"description"`
	Malicious         string `json:"malicious"`
	VulnerabilityType string `json:"vulnerability_type"`
	Application       string `json:"application"`
	CVE               string `json:"cve"`
}

const LLMSystemPrompt = `
Analyze the provided HTTP response. Your response needs to be a raw JSON object response that is not formatted for displaying, without any text outside the JSON, that has the following keys:

description: One paragraph describing the intend of the request, if it is malicous and what application it targets. Describe the payload if the request is malicous. Do not include hostnames, IPs or ports.
malicious: Use the string "yes" if the request is malicious. Else use the string "no".
vulnerability_type: A string containing the Mitre CWE ID, starting with "CWE-" for weakness being exploited. Use an empty string if you don't know.
application: A string with the targetted application/device name. An empty string if you don't know.
cve: The relevant CVE if you know what vulnerability is exploited. A empty string if you don't know.

The request was:
`

func GetNewCachedDescriptionManager(dbClient database.DatabaseClient, llmManager *llm.LLMManager, eventManager analysis.IpEventManager, metrics *DescriberMetrics) *CachedDescriptionManager {
	return &CachedDescriptionManager{
		dbClient:     dbClient,
		llmManager:   llmManager,
		metrics:      metrics,
		eventManager: eventManager,
	}
}

func (b *CachedDescriptionManager) MarkDescriptionFailed(desc *models.RequestDescription) {
	desc.TriageStatus = constants.TriageStatusTypeFailed
	if err := b.dbClient.Update(desc); err != nil {
		slog.Error("failed to update failed description", slog.String("error", err.Error()))
	}

}
func (b *CachedDescriptionManager) GenerateLLMDescriptions(workCount int64) (int64, error) {

	descs, err := b.dbClient.SearchRequestDescription(0, workCount, fmt.Sprintf("triage_status:%s", constants.TriageStatusTypePending))
	if err != nil {
		return 0, fmt.Errorf("failed to get pending descriptions: %w", err)
	}

	if len(descs) == 0 {
		return 0, nil
	}

	var prompts []string
	promptMap := make(map[string]*QueueEntry, workCount)

	for _, desc := range descs {
		reqs, err := b.dbClient.SearchRequests(0, 1, fmt.Sprintf("id:%d", desc.ExampleRequestID))
		if err != nil {
			slog.Error("failed to get request", slog.Int64("id", desc.ExampleRequestID), slog.String("error", err.Error()))
			continue
		}

		if len(reqs) == 0 {
			slog.Error("failed to get request", slog.Int64("id", desc.ExampleRequestID))
			continue
		}

		slog.Debug("Describing request for URI", slog.String("uri", reqs[0].Uri), slog.String("hash", reqs[0].CmpHash))
		prompt := fmt.Sprintf("%s\n%s", LLMSystemPrompt, reqs[0].Raw)
		prompts = append(prompts, prompt)

		promptMap[prompt] = &QueueEntry{
			Request:            reqs[0],
			RequestDescription: desc,
		}
	}

	start := time.Now()
	result, err := b.llmManager.CompleteMultiple(prompts, false)
	if err != nil {
		if len(result) == 0 {
			return 0, fmt.Errorf("failed to complete all LLM requests: %w", err)
		} else {
			slog.Error("failed to complete LLM request", slog.String("error", err.Error()))
		}
	}

	b.metrics.completeMultipleResponsetime.Observe(time.Since(start).Seconds())
	for prompt, completion := range result {
		var llmResult LLMResult
		if err := json.Unmarshal([]byte(completion), &llmResult); err != nil {
			b.MarkDescriptionFailed(&promptMap[prompt].RequestDescription)
			return 0, fmt.Errorf("failed to parse LLM result: %w, result: %s", err, completion)
		}

		bh := promptMap[prompt].RequestDescription
		bh.SourceModel = b.llmManager.LoadedModel()
		bh.AIDescription = llmResult.Description
		bh.AIVulnerabilityType = llmResult.VulnerabilityType
		bh.AIApplication = llmResult.Application
		bh.TriageStatus = constants.TriageStatusTypeDone

		if llmResult.Malicious == "yes" || llmResult.Malicious == "no" {
			bh.AIMalicious = llmResult.Malicious
		}

		if len(llmResult.CVE) <= 15 {
			bh.AICVE = llmResult.CVE
		}

		if err := b.dbClient.Update(&bh); err != nil {
			return 0, fmt.Errorf("failed to insert description: %w: %+v", err, bh)
		}

		req := promptMap[prompt].Request
		// If the rule is 0 then no existing rule matched. In this case if the AI
		// says the request was malicious then we want to raise an event.
		if req.RuleID == 0 && llmResult.Malicious == "yes" {
			detail := ""
			if bh.AIVulnerabilityType != "" {
				detail = fmt.Sprintf("vulnerability type: %s", bh.AIVulnerabilityType)
			}

			b.eventManager.AddEvent(&models.IpEvent{
				IP:            req.SourceIP,
				HoneypotIP:    req.HoneypotIP,
				Source:        constants.IpEventSourceAI,
				RequestID:     req.ID,
				SourceRef:     fmt.Sprintf("%d", bh.ID),
				SourceRefType: constants.IpEventRefTypeRequestDescriptionId,
				Type:          constants.IpEventTrafficClass,
				Subtype:       constants.IpEventSubTypeTrafficClassMalicious,
				Details:       detail,
			})
		}

		delete(promptMap, prompt)
	}

	// Anything left in the original map was not completed by the LLM. We
	// therefore update these in the database with a failed status so that we can
	// try again later.
	for _, detail := range promptMap {
		b.MarkDescriptionFailed(&detail.RequestDescription)
	}

	return int64(len(descs)), nil
}

type FakeDescriptionManager struct {
	addNewHashError error
}

func (f *FakeDescriptionManager) MaybeAddNewHash(hash string, req *models.Request) error {
	return f.addNewHashError
}

func (f *FakeDescriptionManager) Start() {}
