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
package preprocess

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"lophiid/pkg/llm/code"
	"lophiid/pkg/llm/file"
	"lophiid/pkg/llm/shell"
	"lophiid/pkg/llm/sql"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"path/filepath"
	"strings"
	"time"
)

const (
	llmResultSuccess = "success"
	llmResultFailed  = "failed"
)

// Error returned when the request is not going to be processed.
var ErrNotProcessed = errors.New("is not processed")

type PreProcessInterface interface {
	MaybeProcess(req *models.Request) (*PreProcessResult, *PayloadProcessingResult, error)
	Process(req *models.Request) (*PreProcessResult, *PayloadProcessingResult, error)
}

type PreProcess struct {
	triageLLMManager llm.LLMManagerInterface
	shellClient      shell.ShellClientInterface
	codeEmu          code.CodeSnippetEmulatorInterface
	fileEmu          file.FileAccessEmulatorInterface
	sqlEmu           sql.SqlInjectionEmulatorInterface
	metrics          *PreprocessMetrics
}

type PreProcessResult struct {
	HasPayload        bool   `json:"has_payload" jsonschema_description:"This is a boolean field. Use the value 'true' if the request has a payload, such as to execute a command or inject code or open a file. Otherwise use the value 'false'"`
	TargetedParameter string `json:"targeted_parameter" jsonschema_description:"The name of the HTTP URL/body parameter that is targeted. Use an empty string if you don't know. Use the header name if the payload is in a header and use __body__ if the payload is in the body but without a specific parameter"`
	PayloadType       string `json:"payload_type" jsonschema_description:"The type of payload. Can be \"SHELL_COMMAND\", \"FILE_ACCESS\", \"CODE_EXECUTION\", \"SQL_INJECTION\", \"FILE_UPLOAD\" and \"UNKNOWN\" (if you don't know)"`
	Payload           string `json:"payload" jsonschema_description:"The payload if there is one. Empty otherwise"`
	Target            string `json:"target" jsonschema_description:"The target resource of the payload, such as a filename for file operations or a table name for SQL. Empty if not applicable"`
}

type PayloadProcessingResult struct {
	Output         string
	Headers        string
	TmpContentRule *models.TemporaryContentRule
	SqlIsBlind     bool
	SqlDelayMs     int
}

var ProcessPrompt = `
Analyze the provided HTTP request and tell me in the JSON response whether the request has a payload in the has_payload field using a boolean (true or false) . Tell me the name of the HTTP URL/body parameter that is targeted in the targeted_parameter field or leave it empty if no parameter is targeted or when you don't know. If the payload is in the body of the request but not tied to a specific parameter then use "__body__" as the targeted_parameter field. If the payload is in a header then use the header name as targeted_parameter field. Last but not least: tell me what kind of payload it is (payload_type) and you can choose between the strings:

"FILE_UPLOAD" for file upload attempts. These are typically POST requests where the attacker uploads code.
"CODE_EXECUTION" for attempts to execute code (like with <?php tags) but note that code execution attempts via file uploading need to be marked as type FILE_UPLOAD.
"SHELL_COMMAND" for anything that looks like shell/cli commands
"FILE_ACCESS" for attempts to access a file (e.g. /etc/passwd)
"SQL_INJECTION" for SQL injection attempts (e.g. ' OR 1=1, UNION SELECT)
"UNKNOWN" for when the payload type doesn't fall into the above categories.

When in doubt between CODE_EXECUTION and FILE_UPLOAD: chose FILE_UPLOAD.

If you chose "SHELL_COMMAND" then provide the shell commands in the 'payload' field.
If you chose "FILE_ACCESS" then provide the filename (full path) in the 'payload' field.
If you chose "FILE_UPLOAD" then provide the filename (full path) of the uploaded file in the target field and the uploaded file itself in the 'payload' field (original bytes of the file, no summary).
If you chose "CODE_EXECUTION" then provide the code snippet that was attempted to be executed in the 'payload' field.
If you chose "SQL_INJECTION" then provide the SQL injection payload in the 'payload' field.
If you chose "UNKNOWN" then provide whatever the payload is in the 'payload' field.

The request is:

`

type FakePreProcessor struct {
	ResultToReturn *PreProcessResult
	PayloadResult  *PayloadProcessingResult
	ErrorToReturn  error
}

func (f *FakePreProcessor) MaybeProcess(req *models.Request) (*PreProcessResult, *PayloadProcessingResult, error) {
	return f.ResultToReturn, f.PayloadResult, f.ErrorToReturn
}

func (f *FakePreProcessor) Process(req *models.Request) (*PreProcessResult, *PayloadProcessingResult, error) {
	return f.ResultToReturn, f.PayloadResult, f.ErrorToReturn
}

func NewPreProcess(triageLLMManager llm.LLMManagerInterface, shellClient shell.ShellClientInterface, codeEmulator code.CodeSnippetEmulatorInterface, fileEmulator file.FileAccessEmulatorInterface, sqlEmulator sql.SqlInjectionEmulatorInterface, metrics *PreprocessMetrics) *PreProcess {
	triageLLMManager.SetResponseSchemaFromObject(PreProcessResult{}, "request_information")
	return &PreProcess{triageLLMManager: triageLLMManager, shellClient: shellClient, codeEmu: codeEmulator, fileEmu: fileEmulator, sqlEmu: sqlEmulator, metrics: metrics}
}

// Case-sensitive patterns to detect potentially malicious payloads.
var caseSensitivePatterns = []string{
	"echo", "expr", "cat", "/etc", "/var", ".ini", ".log", ".txt", ".php",
	".jsp", ".jar", "/bin/", "java.", "<%", "<?php", "<?=", "untime",
	"org.apache.", "request.", "out.", "ruby", "eval", "exec", "import",
	"subprocess", "shell", "wget", "require", "curl", "busybox", "--",
	"\\-\\-", "phpinfo",
}

// Case-insensitive patterns to detect potentially malicious payloads.
// These are stored lowercase and matched against lowercased request data.
var caseInsensitivePatterns = []string{
	"md5", "select", "version()", "@@version", "union", "concat", "from",
	"where", "sleep", "benchmark", "waitfor", "delay",
}

// requestContainsAnyPattern checks if the request body or URI contains any of
// the suspicious patterns. It pre-computes the lowercase versions to avoid
// repeated allocations.
func requestContainsAnyPattern(req *models.Request) bool {
	body := req.BodyString()
	uri := req.Uri
	bodyLower := strings.ToLower(body)
	uriLower := strings.ToLower(uri)

	for _, pattern := range caseSensitivePatterns {
		if strings.Contains(body, pattern) || strings.Contains(uri, pattern) {
			return true
		}
	}

	for _, pattern := range caseInsensitivePatterns {
		if strings.Contains(bodyLower, pattern) || strings.Contains(uriLower, pattern) {
			return true
		}
	}

	return false
}

// MaybeProcess returns true if the request was handled.
func (p *PreProcess) MaybeProcess(req *models.Request) (*PreProcessResult, *PayloadProcessingResult, error) {
	if !requestContainsAnyPattern(req) {
		return nil, nil, ErrNotProcessed
	}

	return p.Process(req)
}

func (p *PreProcess) Process(req *models.Request) (*PreProcessResult, *PayloadProcessingResult, error) {
	startTime := time.Now()

	defer func() {
		p.metrics.totalFullPreprocessTime.Observe(time.Since(startTime).Seconds())
	}()

	res, err := p.Complete(req)
	if err != nil {
		p.metrics.resultOfPayloadLLMRequests.WithLabelValues(llmResultFailed).Add(1)
		return nil, nil, fmt.Errorf("processing request: %w", err)
	}

	p.metrics.resultOfPayloadLLMRequests.WithLabelValues(llmResultSuccess).Add(1)
	p.metrics.payloadLLMResponseTime.Observe(time.Since(startTime).Seconds())

	if !res.HasPayload {
		return res, nil, nil
	}

	switch res.PayloadType {
	case constants.TriagePayloadTypeShellCommand:
		// if nil then the shell client is disabled
		if p.shellClient == nil {
			return nil, nil, nil
		}
		slog.Debug("Running shell command", slog.String("command", res.Payload))
		shellStartTime := time.Now()
		ctx, err := p.shellClient.RunCommand(req, res.Payload)
		if err != nil {
			return nil, nil, fmt.Errorf("running shell command: %w", err)
		}
		p.metrics.shellLLMResponseTime.Observe(time.Since(shellStartTime).Seconds())

		return res, &PayloadProcessingResult{Output: ctx.Output}, nil

	case constants.TriagePayloadTypeFileAccess:
		if p.fileEmu == nil {
			return nil, nil, nil
		}
		slog.Debug("Running file emulator", slog.String("file", res.Payload))
		fileStartTime := time.Now()
		fRes, err := p.fileEmu.Emulate(req, res.Payload)
		if err != nil {
			return nil, nil, fmt.Errorf("running file emulator: %w", err)
		}

		p.metrics.fileEmuLLMResponseTime.Observe(time.Since(fileStartTime).Seconds())

		return res, &PayloadProcessingResult{Output: fRes}, nil

	case constants.TriagePayloadTypeCodeExec:
		// If nil then the code emulator is disabled
		if p.codeEmu == nil {
			return nil, nil, nil
		}

		slog.Debug("Running code emulator", slog.String("code", res.Payload))
		emuStartTime := time.Now()
		cRes, err := p.codeEmu.Emulate(req, res.Payload)
		if err != nil {
			return nil, nil, fmt.Errorf("running code emulator: %w", err)
		}

		p.metrics.codeEmuLLMResponseTime.Observe(time.Since(emuStartTime).Seconds())
		return res, &PayloadProcessingResult{Output: string(cRes.Stdout), Headers: string(cRes.Headers)}, nil

	case constants.TriagePayloadTypeSqlInjection:
		if p.sqlEmu == nil {
			slog.Error("sql emulator disabled")
			return nil, nil, nil
		}
		slog.Debug("Running sql emulator", slog.Int64("request_id", req.ID), slog.String("payload", res.Payload))
		sqlStartTime := time.Now()
		sRes, err := p.sqlEmu.Emulate(req, res.Payload)
		if err != nil {
			return nil, nil, fmt.Errorf("running sql emulator: %w", err)
		}

		p.metrics.sqlEmuLLMResponseTime.Observe(time.Since(sqlStartTime).Seconds())

		return res, &PayloadProcessingResult{Output: sRes.Output, SqlIsBlind: sRes.IsBlind, SqlDelayMs: sRes.DelayMs}, nil

	case constants.TriagePayloadTypeFileUpload:

		fileName := strings.TrimSpace(filepath.Base(res.Target))
		if fileName == "" {
			return nil, nil, fmt.Errorf("no filename found for upload")
		}

		if len(fileName) < 4 {
			return nil, nil, fmt.Errorf("filename too short: %s", fileName)
		}

		if len(fileName) > 2048 {
			return nil, nil, fmt.Errorf("filename too long: %s", fileName)
		}

		slog.Debug("Handling file upload", slog.Int64("request_id", req.ID), slog.Int64("session_id", req.SessionID), slog.String("file", fileName))

		// Get the /24 for the source IP. We will limit access to the rule/content
		// to only IPs in this network. This in order to prevent abuse.
		net, err := util.Get24NetworkString(req.SourceIP)
		if err != nil {
			return nil, nil, fmt.Errorf("getting network: %w", err)
		}

		tmpContentRule := models.TemporaryContentRule{
			Content: models.Content{
				HasCode:     true,
				Name:        fmt.Sprintf("Temp content: %s-%d", fileName, req.ID),
				Data:        []byte(res.Payload),
				StatusCode:  constants.HTTPStatusCodeOK,
				Server:      "Apache",
				ContentType: "text/html",
			},
			Rule: models.ContentRule{
				Uri:          fileName,
				UriMatching:  constants.MatchingTypeContains,
				BodyMatching: constants.MatchingTypeNone,
				Enabled:      true,
				AllowFromNet: &net,
				// Next we use the request ID for the app ID. This is not an error. We
				// need some value there and do not want to create an app at the moment.
				AppID:            req.ID,
				Method:           constants.HTTPMethodAny,
				RequestPurpose:   constants.RequestPurposeAttack,
				Responder:        constants.ResponderTypeNone,
				ResponderDecoder: constants.ResponderDecoderTypeNone,
			},
		}

		return res, &PayloadProcessingResult{TmpContentRule: &tmpContentRule}, nil

	default:
		slog.Debug("Unknown payload type", slog.Int64("request_id", req.ID), slog.Int64("session_id", req.SessionID), slog.String("type", res.PayloadType), slog.String("payload", res.Payload))

	}

	return res, nil, nil
}

func (p *PreProcess) Complete(req *models.Request) (*PreProcessResult, error) {
	// Remove the Host header from the request data. It is not really important
	// for the AI lookup but removing it makes prompt caching much more efficient.
	requestData := ""
	for line := range strings.SplitSeq(string(req.Raw), "\n") {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			continue
		}
		requestData += line + "\n"
	}

	finalPrompt := fmt.Sprintf("%s%s", ProcessPrompt, requestData)

	res, err := p.triageLLMManager.Complete(finalPrompt, true)
	if err != nil {
		return nil, fmt.Errorf("error getting LLM response: %w", err)
	}

	if res.FromCache {
		p.metrics.triageResultCacheHits.WithLabelValues(constants.LLMCacheHit).Inc()
	} else {
		p.metrics.triageResultCacheHits.WithLabelValues(constants.LLMCacheMiss).Inc()
	}

	result := PreProcessResult{}
	if err := json.Unmarshal([]byte(res.Output), &result); err != nil {
		return nil, fmt.Errorf("error parsing response: %w, json: %s", err, res.Output)
	}

	return &result, nil
}
