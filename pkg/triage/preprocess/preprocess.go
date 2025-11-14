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
	"lophiid/pkg/llm/shell"
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
	MaybeProcess(req *models.Request) (*PreProcessResult, string, error)
	Process(req *models.Request) (*PreProcessResult, string, error)
}

type PreProcess struct {
	triageLLMManager llm.LLMManagerInterface
	shellClient      shell.ShellClientInterface
	codeEmu          code.CodeSnippetEmulatorInterface
	metrics          *PreprocessMetrics
}

type PreProcessResult struct {
	HasPayload  bool   `json:"has_payload" jsonschema_description:"This is a boolean field. Use the value 'true' if the request has a payload, such as to execute a command or inject code or open a file. Otherwise use the value 'false'"`
	PayloadType string `json:"payload_type" jsonschema_description:"The type of payload. Can be \"SHELL_COMMAND\", \"FILE_ACCESS\", "CODE_EXECUTION" and \"UNKNOWN\" (if you don't know)"`
	Payload     string `json:"payload" jsonschema_description:"The payload if there is one. Empty otherwise"`
}

var ProcessPrompt = `
Analyze the provided HTTP request and tell me in the JSON response whether the request has a payload in the has_payload field using a boolean (true or false) . Then tell me what kind of payload it is (payload_type) and you can choose between the strings:

"SHELL_COMMAND" for anything that looks like shell/cli commands
"FILE_ACCESS" for attempts to access a file (e.g. /etc/passwd)
"CODE_EXECUTION" for attempts to execute code (like with <?php tags)
"UNKNOWN" for when the payload type doesn't fall into the above categories.

If you chose "SHELL_COMMAND" then provide the shell commands in the 'payload' field.
If you chose "FILE_ACCESS" then provide the filename (full path) in the 'payload' field.
If you chose "CODE_EXECUTION" then provide the code snippet that was attempted to be executed in the 'payload' field.
If you chose "UNKNOWN" then provide whatever the payload is in the 'payload' field.

The request is:

`

type FakePreProcessor struct {
	ResultToReturn PreProcessResult
	BodyToTReturn  string
	ErrorToReturn  error
}

func (f *FakePreProcessor) MaybeProcess(req *models.Request) (*PreProcessResult, string, error) {
	return &f.ResultToReturn, f.BodyToTReturn, f.ErrorToReturn
}

func (f *FakePreProcessor) Process(req *models.Request) (*PreProcessResult, string, error) {
	return &f.ResultToReturn, f.BodyToTReturn, f.ErrorToReturn
}

func NewPreProcess(triageLLMManager llm.LLMManagerInterface, shellClient shell.ShellClientInterface, codeEmulator code.CodeSnippetEmulatorInterface, metrics *PreprocessMetrics) *PreProcess {
	triageLLMManager.SetResponseSchemaFromObject(PreProcessResult{}, "request_information")
	return &PreProcess{triageLLMManager: triageLLMManager, shellClient: shellClient, metrics: metrics}
}

// MaybeProcess returns true if the request was handled.
func (p *PreProcess) MaybeProcess(req *models.Request) (*PreProcessResult, string, error) {

	// TODO: this is experimental and needs to be replaced with something better.
	if !strings.Contains(req.BodyString(), "echo") &&
		!strings.Contains(req.BodyString(), "expr") &&
		!strings.Contains(req.BodyString(), "cat") &&
		!strings.Contains(req.BodyString(), "passwd") &&
		!strings.Contains(req.BodyString(), "hosts") &&
		!strings.Contains(req.BodyString(), "/bin/") {
		return nil, "", ErrNotProcessed
	}

	return p.Process(req)
}

func (p *PreProcess) Process(req *models.Request) (*PreProcessResult, string, error) {
	startTime := time.Now()

	defer func() {
		p.metrics.totalFullPreprocessTime.Observe(time.Since(startTime).Seconds())
	}()

	res, err := p.Complete(req)
	if err != nil {
		p.metrics.resultOfPayloadLLMRequests.WithLabelValues(llmResultFailed).Add(1)
		return nil, "", fmt.Errorf("processing request: %w", err)
	}

	p.metrics.resultOfPayloadLLMRequests.WithLabelValues(llmResultSuccess).Add(1)
	p.metrics.payloadLLMResponseTime.Observe(time.Since(startTime).Seconds())

	if !res.HasPayload {
		return res, "", nil
	}

	switch res.PayloadType {
	case constants.TriagePayloadTypeShellCommand:
		slog.Debug("Running shell command", slog.String("command", res.Payload))
		shellStartTime := time.Now()
		ctx, err := p.shellClient.RunCommand(req, res.Payload)
		if err != nil {
			return nil, "", fmt.Errorf("running shell command: %w", err)
		}
		p.metrics.shellLLMResponseTime.Observe(time.Since(shellStartTime).Seconds())

		return res, ctx.Output, nil

	case constants.TriagePayloadTypeFileAccess:
		return res, "", nil

	case constants.TriagePayloadTypeCodeExec:
		slog.Debug("Running code emulator", slog.String("code", res.Payload))
		emuStartTime := time.Now()
		cRes, err := p.codeEmu.Emulate(req, res.Payload)
		if err != nil {
			return nil, "", fmt.Errorf("running code emulator: %w", err)
		}

		p.metrics.codeEmuLLMResponseTime.Observe(time.Since(emuStartTime).Seconds())
		return res, string(cRes.Stdout), nil
	}

	return res, "", nil
}

func (p *PreProcess) Complete(req *models.Request) (*PreProcessResult, error) {
	finalPrompt := fmt.Sprintf("%s%s", ProcessPrompt, req.Raw)

	res, err := p.triageLLMManager.Complete(finalPrompt, true)
	if err != nil {
		return nil, fmt.Errorf("error getting LLM response: %w", err)
	}

	result := PreProcessResult{}
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		return nil, fmt.Errorf("error parsing response: %w, json: %s", err, res)
	}

	return &result, nil
}
