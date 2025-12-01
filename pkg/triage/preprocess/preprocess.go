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
	"lophiid/pkg/util/constants"
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
	TargetedParameter string `json:"targeted_parameter" jsonschema_description:"The name of the parameter that is targeted. Use an empty string if you don't know."`
	PayloadType       string `json:"payload_type" jsonschema_description:"The type of payload. Can be \"SHELL_COMMAND\", \"FILE_ACCESS\", \"CODE_EXECUTION\" and \"UNKNOWN\" (if you don't know)"`
	Payload           string `json:"payload" jsonschema_description:"The payload if there is one. Empty otherwise"`
}

type PayloadProcessingResult struct {
	Output     string
	Headers    string
	SqlIsBlind bool
	SqlDelayMs int
}

var ProcessPrompt = `
Analyze the provided HTTP request and tell me in the JSON response whether the request has a payload in the has_payload field using a boolean (true or false) . Tell me the name of the parameter that is targeted in the targeted_parameter field or leave it empty if no parameter is targeted or when you don't know. Then tell me what kind of payload it is (payload_type) and you can choose between the strings:

"CODE_EXECUTION" for attempts to execute code (like with <?php tags)
"SHELL_COMMAND" for anything that looks like shell/cli commands
"FILE_ACCESS" for attempts to access a file (e.g. /etc/passwd)
"SQL_INJECTION" for SQL injection attempts (e.g. ' OR 1=1, UNION SELECT)
"UNKNOWN" for when the payload type doesn't fall into the above categories.

Important: If you see code execution that also has shell/cli commands then always choose CODE_EXECUTION.

If you chose "SHELL_COMMAND" then provide the shell commands in the 'payload' field.
If you chose "FILE_ACCESS" then provide the filename (full path) in the 'payload' field.
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

func RequestHas(req *models.Request, has string) bool {
	return strings.Contains(req.BodyString(), has) || strings.Contains(req.Uri, has)
}

func RequestHasCaseInsensitive(req *models.Request, has string) bool {
	return strings.Contains(strings.ToLower(req.BodyString()), has) || strings.Contains(strings.ToLower(req.Uri), has)
}

// MaybeProcess returns true if the request was handled.
func (p *PreProcess) MaybeProcess(req *models.Request) (*PreProcessResult, *PayloadProcessingResult, error) {

	// TODO: this is experimental and needs to be replaced with something better.
	if !RequestHas(req, "echo") &&
		!RequestHas(req, "expr") &&
		!RequestHas(req, "cat") &&
		!RequestHas(req, "/etc") &&
		!RequestHas(req, "/var") &&
		!RequestHas(req, ".ini") &&
		!RequestHas(req, ".log") &&
		!RequestHas(req, ".txt") &&
		!RequestHas(req, ".php") &&
		!RequestHas(req, ".jsp") &&
		!RequestHas(req, ".jar") &&
		!RequestHas(req, "/bin/") &&
		!RequestHas(req, "java.") &&
		!RequestHas(req, "<%") &&
		!RequestHas(req, "<?php") &&
		!RequestHas(req, "<?=") &&
		!RequestHas(req, "untime") &&
		!RequestHas(req, "org.apache.") &&
		!RequestHas(req, "request.") &&
		!RequestHas(req, "out.") &&
		!RequestHas(req, "ruby") &&
		!RequestHas(req, "eval") &&
		!RequestHas(req, "--") &&
		!RequestHas(req, "\\-\\-") &&
		!RequestHasCaseInsensitive(req, "md5") &&
		!RequestHasCaseInsensitive(req, "select") &&
		!RequestHasCaseInsensitive(req, "version()") &&
		!RequestHasCaseInsensitive(req, "@@version") &&
		!RequestHasCaseInsensitive(req, "union") &&
		!RequestHasCaseInsensitive(req, "concat") &&
		!RequestHasCaseInsensitive(req, "from") &&
		!RequestHasCaseInsensitive(req, "where") &&
		!RequestHasCaseInsensitive(req, "sleep") &&
		!RequestHasCaseInsensitive(req, "benchmark") &&
		!RequestHasCaseInsensitive(req, "waitfor") &&
		!RequestHasCaseInsensitive(req, "delay") &&
		!RequestHas(req, "phpinfo") {
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
		slog.Debug("Running sql emulator", slog.String("payload", res.Payload))
		sqlStartTime := time.Now()
		sRes, err := p.sqlEmu.Emulate(req, res.Payload)
		if err != nil {
			return nil, nil, fmt.Errorf("running sql emulator: %w", err)
		}

		p.metrics.sqlEmuLLMResponseTime.Observe(time.Since(sqlStartTime).Seconds())

		return res, &PayloadProcessingResult{Output: sRes.Output, SqlIsBlind: sRes.IsBlind, SqlDelayMs: sRes.DelayMs}, nil
	default:
		slog.Debug("Unknown payload type", slog.String("payload", res.Payload))

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
