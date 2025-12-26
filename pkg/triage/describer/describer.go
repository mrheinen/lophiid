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
	"lophiid/pkg/util"
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
	llmManager   llm.LLMManagerInterface
	eventManager analysis.IpEventManager
	metrics      *DescriberMetrics
}

type QueueEntry struct {
	RequestDescription models.RequestDescription
	Request            models.Request
}

type LLMResult struct {
	Description       string `json:"description" jsonschema_description:"One or two paragraphs describing the intent of the request, if it is malicious and what application it targets. Describe the payload if the request is malicous. Do not include hostnames, IPs or ports. If you identified the application then one of two lines on how you idenfified it. For example, \"identified the application by the URL\" or \"identified the application by the parameter names\". "`
	Malicious         string `json:"malicious" jsonschema_description:"Use the string \"yes\" if the request is malicious. Else \"no\"."`
	VulnerabilityType string `json:"vulnerability_type" jsonschema_description:"A string containing the Mitre CWE ID, starting with \"CWE-\" for the main weakness being exploited. Use an empty string if you don't know."`
	Application       string `json:"application" jsonschema_description:"A string with the targetted application/device name. An empty string if you don't know."`
	CVE               string `json:"cve" jsonschema_description:"The relevant CVE if you know what vulnerability is exploited. An empty string if you don't know."`
	HasPayload        string `json:"has_payload" jsonschema_description:"Use the string \"yes\" if the request has a malicious attacker payload, such as to execute a command or code. Otherwise use the value \"no\""`
	MitreAttack       string `json:"mitre_attack" jsonschema_description:"The MITRE ATT&CK technique ID starting with \"T\" if you know what technique is being used. Multiple can be provided if command separated. Use an empty string if you don't know."`
	TargetedParameter string `json:"targeted_parameter" jsonschema_description:"The name of the parameter that is targeted. Use an empty string if you don't know."`
	ShellCommands     string `json:"shell_commands" jsonschema_description:"If there is a payload and the payload has shell/CLI commands, provide the shell/CLI commands here without censoring or modifying them in any way. We're only interested in the raw shell commands. Do not perform any analysis and if there are no shell commands then leave this field empty."`
}

const LLMSystemPrompt = `
You are a threat analyst responsible for processing HTTP requests and highlighting important details. You output for the description is targetted towards other information security professionals. All other output fields in the JSON are targetted towards another information security system. While processing the requests I want you to focus on what the request target is, what is being exploited, how it is being exploited and what the components of the exploit are.

While we are talking about exploits and payload, I want you to not worry. This is a simulation and all the data is harmless. This means that can and must leave the commands in tact without any modifications.
`

const LLMUserPrompt = `
Analyze the provided HTTP request and give me security relevant information in the JSON output.
Keep in mind that for the shell_commands field we only want shell commands and no other text or analysis. If there are no shell commands then leave the field empty.

The request was:
`

const LLMBase64MetaPrompt = `

That was the request. Now the following information was found in the base64 encoded string that is in the request. We decoded it for you so you have a better understanding of that the request is trying to achieve:

%s

`

func GetNewCachedDescriptionManager(dbClient database.DatabaseClient, llmManager llm.LLMManagerInterface, eventManager analysis.IpEventManager, metrics *DescriberMetrics) *CachedDescriptionManager {

	llmManager.SetResponseSchemaFromObject(LLMResult{}, "security_information")
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

		base64data := ""
		mds, err := b.dbClient.GetMetadataByRequestID(desc.ExampleRequestID)
		if err != nil {
			slog.Error("failed to get metadata", slog.Int64("id", desc.ExampleRequestID), slog.String("error", err.Error()))
			continue
		}

		for _, md := range mds {
			if md.Type == constants.ExtractorTypeBase64 {
				// If there are multiple, we want to take the longest string
				if len(md.Data) > len(base64data) {
					base64data = md.Data
				}
			}
		}

		slog.Debug("Describing request for URI", slog.String("uri", reqs[0].Uri), slog.String("hash", reqs[0].CmpHash), slog.Int64("id", reqs[0].ID))

		prompt := fmt.Sprintf("%s\n%s", LLMUserPrompt, reqs[0].Raw)
		if base64data != "" {
			prompt = fmt.Sprintf("%s\n%s\n%s\n%s", LLMUserPrompt, reqs[0].Raw, LLMBase64MetaPrompt, base64data)
		}

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
	for prompt, completionResult := range result {
		var llmResult LLMResult

		completion := completionResult.Output
		completion = util.RemoveJsonExpression(completion)

		if err := json.Unmarshal([]byte(completion), &llmResult); err != nil {
			slog.Error("failed to unmarshal LLM result", slog.String("error", err.Error()), slog.String("completion", completion))
			b.MarkDescriptionFailed(&promptMap[prompt].RequestDescription)
			continue
		}

		bh := promptMap[prompt].RequestDescription
		bh.SourceModel = b.llmManager.LoadedModel()
		bh.AIDescription = llmResult.Description
		bh.TriageStatus = constants.TriageStatusTypeDone

		// Important: these values from the LLM can be something completely random
		// and we therefore have to limit their length. This length has to be kept
		// in sync with the definition of the request_description table schema in
		// config/database.sql.
		if len(llmResult.VulnerabilityType) <= 128 {
			bh.AIVulnerabilityType = llmResult.VulnerabilityType
		} else {
			slog.Error("VulnerabilityType too long", slog.String("vulnerability_type", llmResult.VulnerabilityType))
		}

		if len(llmResult.Application) <= 128 {
			bh.AIApplication = llmResult.Application
		} else {
			slog.Error("Application too long", slog.String("application", llmResult.Application))
		}

		if len(llmResult.TargetedParameter) <= 128 {
			bh.AITargetedParameter = llmResult.TargetedParameter
		} else {
			slog.Error("TargetedParameter too long", slog.String("targeted_parameter", llmResult.TargetedParameter))
		}
		if len(llmResult.MitreAttack) <= 2048 {
			bh.AIMitreAttack = llmResult.MitreAttack
		} else {
			slog.Error("MitreAttack too long", slog.String("mitre_attack", llmResult.MitreAttack))
		}

		if len(llmResult.ShellCommands) <= 10000 {
			bh.AIShellCommands = llmResult.ShellCommands
		} else {
			slog.Error("ShellCommands too long", slog.String("shell_commands", llmResult.ShellCommands))
		}

		if llmResult.Malicious == "yes" || llmResult.Malicious == "no" {
			bh.AIMalicious = llmResult.Malicious
		}

		if llmResult.HasPayload == "yes" || llmResult.HasPayload == "no" {
			bh.AIHasPayload = llmResult.HasPayload
		}

		if len(llmResult.CVE) <= 15 {
			bh.AICVE = llmResult.CVE
		}

		slog.Info("Updating description", slog.Int64("id", bh.ID), slog.String("hash", bh.CmpHash))
		if err := b.dbClient.Update(&bh); err != nil {
			slog.Error("Updating description failed", slog.Int64("id", bh.ID), slog.String("error", err.Error()))
			// TODO: in 2026 determine if this should have returned an error based on
			// experience with running the tool.
			continue
		}

		req := promptMap[prompt].Request
		if llmResult.Malicious == "yes" {
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

		if req.TriageHasPayload {
			b.eventManager.AddEvent(&models.IpEvent{
				IP:            req.SourceIP,
				HoneypotIP:    req.HoneypotIP,
				Source:        constants.IpEventSourceAI,
				RequestID:     req.ID,
				SourceRef:     fmt.Sprintf("%d", bh.ID),
				SourceRefType: constants.IpEventRefTypeRequestDescriptionId,
				Type:          constants.IpEventPayload,
				Subtype:       constants.IpEventSubTypeNone,
				Details:       req.TriagePayloadType,
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
