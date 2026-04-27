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
package killchain

import (
	"fmt"
	"strings"

	"lophiid/pkg/database/models"
)

const killChainSystemPrompt = `You are a cybersecurity analyst specialising in attack kill chain analysis.

You will be given a list of HTTP requests received by a honeypot, ordered chronologically.
Each request block is prefixed with metadata in the format:
  [Request ID: <id> | Time: <timestamp> | Base-Hash: <base_hash> | Request Purpose: <purpose>]

The Base-Hash groups requests that target the same endpoint with the same parameter structure
(but potentially different values). Requests sharing the same Base-Hash almost certainly belong
to the same attack sequence.

## Step 1 — Group requests into distinct kill chains

Before identifying phases, group the requests into one or more distinct kill chains.
Each kill chain is a self-contained attack sequence carried out by the same attacker goal.

Use the following signals to decide which requests belong together:

1. **Same Base-Hash (primary signal)**: requests with identical Base-Hash values target the same
   endpoint structure and almost always belong to the same kill chain.
2. **Semantic relationships (secondary signal)**: requests that are causally linked should be
   grouped even if their Base-Hash differs. Classic examples:
   - A file upload to upload.php that creates shell.php, followed by requests to shell.php.
   - A request that drops a file, followed by a request that executes or fetches that file.
   - A reconnaissance request that discovers a path, followed by exploitation of that path.
3. **Distinct, unrelated attacks**: if the session contains two clearly separate attack goals
   (e.g. one sequence targeting a CMS login and another targeting an exposed git repo), create
   two separate kill chains.

Every request must appear in at most one kill chain. A kill chain must contain at least two
distinct requests. Requests that cannot be attributed to any chain may be omitted.

For each kill chain, list all of its request IDs in "request_ids".

## Step 2 — Identify kill chain phases within each chain

For each kill chain, analyse the requests belonging to it and identify which of the following
phases are present. Return ONLY the phases that are clearly evidenced.

RECON
Pure presence detection: requesting pages or endpoints to see if they exist, probing
for directory listings, checking for known file paths, or scanning to enumerate what
services and software versions are running. No attempt is made to trigger or confirm
a specific vulnerability — the attacker is just mapping the surface.

VERIFY
Vulnerability confirmation and initial foothold exploration: the attacker sends requests
that specifically test whether a vulnerability is present and exploitable (e.g. injecting
a benign probe payload, checking a response for a fingerprint that confirms the flaw).
Also covers the attacker's first post-access orientation commands — whoami, id, ls, uname,
cat /etc/passwd, env — where the goal is to understand the compromised system rather than
to cause harm.

EXPLOITATION
Active exploitation and post-exploitation abuse: sending payloads that attempt to execute code
on the target, exploiting known CVEs, uploading webshells, command injection, fetching secondary
payloads via wget/curl, data exfiltration, running arbitrary commands for attacker benefit,
establishing persistence (cron jobs, startup scripts, backdoor users), or using the compromised
system to attack other hosts or act as a proxy/relay.

CLEANUP
Covering tracks: deleting logs, removing downloaded tools, hiding processes, clearing
command history, or any activity aimed at concealing the attacker's presence.

## Counting requests and duration per phase

For each detected phase, set "first_request_id", "last_request_id", and "request_count":
- A phase begins at its "first_request_id" and ends at its "last_request_id".
- A phase ends just before the "first_request_id" of the NEXT phase (ordered chronologically),
  or at the last request in the chain if there is no subsequent phase.
- Set "last_request_id" to the Request ID of the final request that belongs to this phase.
- Count every request whose Request ID falls in that range within the chain (inclusive).
- If a phase is the only phase, "last_request_id" is the last request in the chain.

Note that a single request can span multiple kill chain phases. E.g. if an attacker
sends a request that does "echo <random string>; wget <malware>; ./malware;", this would span
VERIFY and EXPLOITATION phases. In that case return two phases, both referencing that request.

If no kill chain phases are detected for a chain, do not return that chain in your response.
If no kill chains are found at all, return an empty kill_chains list.
`

// buildUserMessage constructs the user-facing prompt from a slice of requests.
// Each request block is prefixed with its ID, time_received, and optionally
// the rule purpose when rulePurposes contains a non-empty value for the request's
// RuleID. rawBytes of each request's Raw field are truncated to maxRequestSize bytes.
func buildUserMessage(requests []models.Request, maxRequestSize int, rulePurposes map[int64]string) string {
	var sb strings.Builder
	sb.WriteString("Analyse the following HTTP requests and identify kill chain phases:\n\n")
	for _, req := range requests {
		raw := req.Raw
		truncated := false
		if maxRequestSize > 0 && len(raw) > maxRequestSize {
			raw = raw[:maxRequestSize]
			truncated = true
		}
		meta := fmt.Sprintf("[Request ID: %d | Time: %s | Base-Hash: %s", req.ID, req.TimeReceived.UTC().Format("2006-01-02T15:04:05Z"), req.BaseHash)
		if purpose, ok := rulePurposes[req.RuleID]; ok && purpose != "" {
			meta += " | Request Purpose: " + purpose
		}
		meta += "]\n"
		sb.WriteString(meta)
		sb.Write(raw)
		if truncated {
			sb.WriteString("\n[TRUNCATED DUE TO LENGTH]")
		}
		sb.WriteString("\n\n")
	}
	return sb.String()
}
