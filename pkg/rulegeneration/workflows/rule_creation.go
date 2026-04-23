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
package workflows

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	ruletools "lophiid/pkg/rulegeneration/tools"
	"lophiid/pkg/util/constants"
)

const ruleCreationSystemPrompt = `You are an expert honeypot rule generation agent. Your task is to research a
malicious HTTP request and autonomously create a draft application, content, and
content rule that will make the honeypot respond convincingly to future matching
requests.

All tools return a JSON object with the following envelope:
  {"status": "SUCCESS"|"ERROR", "status_message": "<human-readable text>", "data": <payload or null>}
Always check "status" before acting on "data".

You have the following tools available:
- web_search(query): Search the web
- fetch_url(url): Fetch the text content of a URL
- list_existing_rules(uri_pattern): Check for duplicate active rules
- list_apps(): List known applications
- search_github_code(query): Search GitHub for exploit proof-of-concepts and related code; returns raw file URLs
- create_draft(app, content, rule): Create the final draft records (call once)

URL TRACKING (throughout the entire workflow)
From the very first step, maintain a running list of every URL you encounter or visit.
You will pass this complete list as the top-level "links" array in create_draft. Never discard a URL
once added — keep appending. Always provide "links" at the top level — even when using an existing app.
The list should include, but is not limited to:
  - Every ExploitDB URL found in web search results (not just the one you fetched)
  - Every GitHub raw file URL returned by search_github_code (not just the one you fetched)
  - Every analysis/blog page URL you visit in W-2b
  - The NVD page URL
  - Any vendor advisory URL(s)

Follow these steps in order:

W-1 EXPLOIT SEARCH

First prepare the base search string that we will be using in this step. If the request has
no body (e.g. no content-length or content-length = 0) then you need to focus on only the URI.
In this case you should use the URI as the search string but make sure you remove any payload
data that might be present (e.g. like shell commands). For example
"/device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___&mdb=sos&mdc=cat%20/proc/cpuinfo" would become
"/device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___&mdb=sos&mdc=" as the search string.

If there is a body then process the URI in the same way and if that is not distinct enough then I
want you to also include a snippet of the body in the search string (as a separate word). Make sure
to take a snippet of the body that looks like it belongs to the applications logic and do not take a
snippet that has, for example, data that can be unique to a single exploitation attempt.

Do a web search for the search string in combination with "exploitdb"
(e.g. web_search("/device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___&mdb=sos&mdc= exploitdb")).
Try up to three distinct search queries before proceeding without an exploit link.
Add ALL ExploitDB URLs from the search results to your running links list, even if you only
fetch one of them.

Also search GitHub for exploit proof-of-concepts using search_github_code with a
query such as <search string> + " CVE". Go through the returned raw
file URLs with fetch_url until you find an exploit or exhausted the list (whatever comes first).
A file is an exploit if it does one or several of the following things: references a CVE number,
uses an HTTP client or library to send a payload, checks the server response for success/failure, and contains words like
exploit, payload, attack, shell, success, or failed. Stop fetching as soon as an
exploit is confirmed.  If these first results to not contain an exploit then search for
"<URI> PoC" instead and try again.
Add ALL GitHub raw file URLs returned by search_github_code to your running links list,
regardless of whether you fetched them.

W-2a EXPLOIT ANALYSIS
If you found exploit(s), fetch it/them with fetch_url. Extract:
- Target application name (keep short)
- CVE ID(s) if mentioned (newline-separated for multiple)
- Request purpose: EXPLOITATION if it is a clear attack/abuse, RECON if reconnaissance, UNKNOWN otherwise
- The expected HTTP response body (Data), status code, Content-Type, Server header, and any extra headers
Add the URL of every exploit file you fetched to your running links list.

W-2b VULNERABILITY ANALYSIS
Now search for "<CVE> analysis" look for web pages that do a through analysis of the vulnerability and exploitation
the pages usually contain more information on how to exploit the vulnerability and what the expected response should be.
From the search result, visit up to 3 analysis pages and review them for the expected response.
Add the URL of every analysis page you visit to your running links list.

W-3 CVE RESOLUTION
If a CVE was found but no NVD link, build the URL:
  https://nvd.nist.gov/vuln/detail/<CVE>
Add this URL to your running links list.

W-4 NVD VERSION LOOKUP
Fetch the NVD page for the CVE. Look for a "Vendor Advisory" link first.
If found, fetch the vendor advisory and extract the affected version string.
If no advisory or no version found there, extract version strings from the NVD page itself.
Use "unknown" if no version can be determined.
Add the NVD URL and any vendor advisory URL(s) to your running links list.

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
- description: a concise summary of what was found, e.g. "CVE-2021-44228 Log4Shell RCE in Apache Log4j — JNDI lookup exploit targeting /log4j path"
- links: your complete running links list at the TOP LEVEL of create_draft (all ExploitDB URLs, all GitHub raw file URLs, all analysis page URLs, NVD page URL, vendor advisory URLs — omit only if the list is truly empty). This is separate from app.links and must always be provided.
- app (if new): name, version (use "unknown" if not found), vendor (use "unknown" if not sure),
  cves (array, omit if none), links (same complete running links list as the top-level links field)
- content: name (short, descriptive), description (explain how Data was derived, include reference links),
  data (realistic response body based on the exploit or matching application behaviour. Make it look realistic and successful.
  IMPORTANT: the request you are given contains a specific payload (e.g. "cat /etc/passwd", a shell command, SQL, etc.).
  Future requests will carry different payloads. Never hard-code the payload output into data.
  Instead, place the exact literal string %%%LOPHIID_PAYLOAD_RESPONSE%%% at the position in data where the payload-specific output would appear.
  Everything else in data (surrounding structure, headers, framing) should be realistic and complete.), status_code, content_type (if relevant),
  server (if relevant), headers (if relevant)
- rule: uri (from request), uri_matching (exact/prefix/regex/contains, note that request.uri contains parameters so if the uri is '/blah?a=b' then using exact will match on that entire string. Important !! If you remove anything from the original uri then you need to use either 'prefix' or 'contains' (which is the safest option) ),
  body (very optional and for POST and PUT only, if needed for specificity but in that case make sure to only use strings that are part of the application and not part of the payload. Do not use shell commands, code execution strings, filenames or sql injections here!), body_matching (use "contains" when body is set, otherwise use none),
  method (from request), request_purpose (EXPLOITATION/RECON/UNKNOWN), app_id (if existing app)

All is_draft and enabled flags are set automatically — do not include them.
TCP ports must always be left empty.`

// RuleCreationWorkflow researches a malicious HTTP request and creates draft DB records.
type RuleCreationWorkflow struct {
	toolset    *RuleCreationToolSet
	llmManager llm.LLMManagerInterface
	req        models.Request
	desc       models.RequestDescription
}

// NewRuleCreationWorkflow creates a new RuleCreationWorkflow.
func NewRuleCreationWorkflow(
	llmManager llm.LLMManagerInterface,
	toolset *RuleCreationToolSet,
	req models.Request,
	desc models.RequestDescription,
) *RuleCreationWorkflow {
	return &RuleCreationWorkflow{
		toolset:    toolset,
		llmManager: llmManager,
		req:        req,
		desc:       desc,
	}
}

// Run researches the request and description and creates draft DB records.
func (w *RuleCreationWorkflow) Run(ctx context.Context) error {
	slog.Info("rule creation workflow starting",
		slog.Int64("request_id", w.req.ID),
		slog.String("method", w.req.Method),
		slog.String("uri", w.req.Uri),
		slog.String("ai_description", w.desc.AIDescription))

	userMsg := buildUserMessage(w.req, w.desc)

	msgs := []llm.LLMMessage{
		{Role: constants.LLMClientMessageSystem, Content: ruleCreationSystemPrompt},
		{Role: constants.LLMClientMessageUser, Content: userMsg},
	}

	toolList := w.toolset.BuildTools()

	// Inject the originating request ID into the create_draft tool so it is
	// stored in the RuleManagementLog without leaking it into the LLM schema.
	// TODO: think about finding a cleaner way to do this. For example, perhaps just let the
	// LLM pass the request ID as an argument, but that would require changing the tool schema.
	reqID := w.req.ID
	for i, t := range toolList {
		if t.Name == "create_draft" {
			origFn := t.Function
			toolList[i].Function = func(ctx context.Context, args string) (string, error) {
				var input ruletools.CreateDraftInput
				if err := json.Unmarshal([]byte(args), &input); err != nil {
					slog.Warn("create_draft: could not inject base_request_id, passing args through",
						slog.String("error", err.Error()))
					return origFn(ctx, args)
				}
				input.BaseRequestID = reqID
				injected, err := json.Marshal(input)
				if err != nil {
					return ruletools.GetJSONErrorMessage("Internal error marshaling args", nil), fmt.Errorf("re-serializing create_draft input: %w", err)
				}
				return origFn(ctx, string(injected))
			}
			break
		}
	}

	slog.Info("rule creation workflow invoking LLM tool loop",
		slog.Int64("request_id", w.req.ID),
		slog.Int("max_iterations", maxAgentToolIterations))

	result, err := w.llmManager.CompleteWithTools(msgs, toolList, maxAgentToolIterations, false)
	if err != nil {
		return fmt.Errorf("LLM tool loop failed for request %d: %w", w.req.ID, err)
	}

	slog.Info("rule creation workflow complete",
		slog.Int64("request_id", w.req.ID),
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
