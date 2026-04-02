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
package rulegeneration

import (
	"context"
	"fmt"
	"log/slog"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"lophiid/pkg/util/constants"
	"time"
)

const maxAgentToolIterations = 50

const systemPrompt = `You are an expert honeypot rule generation agent. Your task is to research a
malicious HTTP request and autonomously create a draft application, content, and
content rule that will make the honeypot respond convincingly to future matching
requests.

You have the following tools available:
- web_search(query): Search the web
- fetch_url(url): Fetch the text content of a URL
- list_existing_rules(uri_pattern): Check for duplicate active rules
- list_apps(): List known applications
- create_draft(app, content, rule): Create the final draft records (TERMINAL — call once)

Follow these steps in order:

W-1 EXPLOIT SEARCH
Search for the URI combined with "exploitdb" (e.g. web_search("<uri> exploitdb")).
If no useful results and the URI contains encoded characters or payload fragments,
strip those and retry with just the clean path. For POST requests with generic
paths, augment the query with a distinctive snippet from the body.
Try up to three distinct search queries before proceeding without an exploit link.

W-2a EXPLOIT ANALYSIS
If you found an ExploitDB (or similar) page that has the exploit, fetch it with fetch_url. Extract:
- Target application name (keep short)
- CVE ID(s) if mentioned (newline-separated for multiple)
- Request purpose: ATTACK if it is a clear attack, RECON if reconnaissance, UNKNOWN otherwise
- The expected HTTP response body (Data), status code, Content-Type, Server header, and any extra headers

W-2b VULNERABILITY ANALYSIS
Now search for "<CVE> analysis" look for web pages that do a through analysis of the vulnerability and exploitation
the pages usually contain more information on how to exploit the vulnerability and what the expected response should be.
From the search result, visit up to 3 analysis pages and review them for the expected response.

W-3 CVE RESOLUTION
If a CVE was found but no NVD link, build the URL:
  https://nvd.nist.gov/vuln/detail/<CVE>

W-4 NVD VERSION LOOKUP
Fetch the NVD page for the CVE. Look for a "Vendor Advisory" link first.
If found, fetch the vendor advisory and extract the affected version string.
If no advisory or no version found there, extract version strings from the NVD page itself.
Use "unknown" if no version can be determined.
Set Application.Links to the advisory URL(s) found. Include the NVD page and/or the exploit URL as additional entries.

W-5 DUPLICATE CHECK
Call list_existing_rules(uri_pattern) with the request URI. If an identical active
rule already exists, stop and respond: "Duplicate rule already exists: <id>".

W-6 APP LOOKUP
Call list_apps() to check if the target application already exists in the database.
If it does, use its ID as rule.app_id and omit the app object from create_draft.
If it does not exist, prepare a new app object for create_draft (is_draft will be
set to true automatically).

W-7 SPECIFICITY CHECK & CREATE DRAFT
Before creating the rule, verify the URI pattern is specific enough — it must not
match unrelated paths. Prefer exact or prefix matching over regex or contains.
If the URI is very generic (e.g. "/" or "/index.php"), tighten it using the HTTP
method and, for POST requests, a distinctive body pattern.

Then call create_draft with:
- app (if new): name, version (use "unknown" if not found), vendor (use "unknown" if not sure),
  cves (array, omit if none), links (array of advisory/NVD/exploit URLs, omit if none)
- content: name (short, descriptive), description (explain how Data was derived, include reference links),
  data (realistic response body either based on information from the exploit or generate something that would fit this type of application/request. Make the response look realistic, relevant to the request and make it look successful), status_code, content_type (if relevant),
  server (if relevant), headers (if relevant)
- rule: uri (from request), uri_matching (exact/prefix/regex/contains, note that request.uri contains parameters so if the uri is '/blah?a=b' then using exact will match on that entire string. Important !! If you remove anything from the original uri then you need to use either 'prefix' or 'contains' (which is the safest option) ),
  body (very optional and for POST and PUT only, if needed for specificity but in that case make sure to only use strings that are part of the application and not part of the payload. Do not use shell commands, code execution strings, filenames or sql injections here!), body_matching (use "contains" when body is set, otherwise use none),
  method (from request), request_purpose (ATTACK/RECON/UNKNOWN), app_id (if existing app)

All is_draft and enabled flags are set automatically — do not include them.
TCP ports must always be left empty.`

// Agent orchestrates the rule-generation workflow for a single request.
type Agent struct {
	llmManager llm.LLMManagerInterface
	toolSet    *ToolSet
}

// NewAgent creates a new Agent.
func NewAgent(llmManager llm.LLMManagerInterface, toolSet *ToolSet) *Agent {
	return &Agent{
		llmManager: llmManager,
		toolSet:    toolSet,
	}
}

// Process researches the given request+description and creates draft DB records.
// It returns an error only for infrastructure failures; "no result" situations
// are logged and return nil.
func (a *Agent) Process(ctx context.Context, req models.Request, desc models.RequestDescription) error {
	slog.Info("rule generation agent starting",
		slog.Int64("request_id", req.ID),
		slog.String("method", req.Method),
		slog.String("uri", req.Uri),
		slog.String("ai_description", desc.AIDescription))

	userMsg := buildUserMessage(req, desc)

	msgs := []llm.LLMMessage{
		{Role: constants.LLMClientMessageSystem, Content: systemPrompt},
		{Role: constants.LLMClientMessageUser, Content: userMsg},
	}

	tools := a.toolSet.BuildTools()

	slog.Info("rule generation agent invoking LLM tool loop",
		slog.Int64("request_id", req.ID),
		slog.Int("max_iterations", maxAgentToolIterations))

	result, err := a.llmManager.CompleteWithTools(msgs, tools, maxAgentToolIterations, false)
	if err != nil {
		return fmt.Errorf("LLM tool loop failed for request %d: %w", req.ID, err)
	}

	slog.Info("rule generation agent complete",
		slog.Int64("request_id", req.ID),
		slog.String("result", result.Output))

	return nil
}

// buildUserMessage constructs the initial user message from the request and description.
func buildUserMessage(req models.Request, desc models.RequestDescription) string {
	body := ""
	if len(req.Body) > 0 {
		truncated := req.Body
		if len(truncated) > 2048 {
			truncated = truncated[:2048]
		}
		body = fmt.Sprintf("\nRequest body (first 2048 bytes):\n%s", string(truncated))
	}

	return fmt.Sprintf(`Analyse the following malicious HTTP request and follow the workflow steps W-1 through W-7.

Method:  %s
URI:     %s
Headers: %v
Body:    %s

AI classification: %s
AI description:    %s
AI application:    %s
AI vuln type:      %s
AI CVE:            %s

Proceed with the full workflow now.`,
		req.Method,
		req.Uri,
		req.Headers,
		body,
		desc.AIMalicious,
		desc.AIDescription,
		desc.AIApplication,
		desc.AIVulnerabilityType,
		desc.AICVE,
	)
}

// NewAgentFromConfig is a convenience constructor that wires up an Agent from
// a database client, LLM manager, and web search config.
func NewAgentFromConfig(
	ctx context.Context,
	dbClient database.DatabaseClient,
	llmManager llm.LLMManagerInterface,
	searchCfg WebSearchConfig,
	requestID int64,
	dryRun bool,
) (*Agent, error) {
	searchTimeout, err := time.ParseDuration(searchCfg.Timeout)
	if err != nil {
		return nil, fmt.Errorf("invalid web_search.timeout %q: %w", searchCfg.Timeout, err)
	}

	var searchProvider SearchProvider
	switch searchCfg.Provider {
	case "tavily":
		if searchCfg.APIKey == "" {
			return nil, fmt.Errorf("tavily provider requires web_search.api_key")
		}
		searchProvider = NewTavilySearchProvider(searchCfg.APIKey, searchTimeout)
	default:
		return nil, fmt.Errorf("unknown search provider %q", searchCfg.Provider)
	}

	toolSet := NewToolSet(dbClient, searchProvider, requestID, dryRun)
	return NewAgent(llmManager, toolSet), nil
}
