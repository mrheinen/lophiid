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

package interpreter

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"lophiid/pkg/llm/shell"
	"lophiid/pkg/llm/tools"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
)

type InterOutput struct {
	Output  string `json:"stdout" jsonschema_description:"The output of the code"`
	Headers string `json:"headers" jsonschema_description:"HTTP headers output of the code"`
}

const CodeInterpreterSystemPrompt = `
You are given web application code and an HTTP request. It is your job to determine what output the web application code would generate if it was executed and tasked with handling the given HTTP request. Note that your job is not to actually execute this code, which would be dangerous. Instead I need you to use your knowledge to determine what the output of the web application would be if it was requested with the given request. Pay attention to what parameters and headers the request sends and how the application processes them.

If the web application would like to execute shell commands then you MUST make use of the 'shell_command_to_output' tool. Even do this for commands that don't make sense to you or for which you don't expect any output. The number one rule is that each and every shell command must be given to the 'shell_command_to_output' tool.

Reply with a JSON response where the following fields are present:

stdout: The output of the code. When determining what this output will be, assume that all operations in the code are successful. Use an empty string if there is no output.
headers: If the code outputs HTTP headers then I want you to store them in this field:  each "header: value" pair should be on their own line. Leave empty otherwise.
`

const ApplicationRequestTemplate = `
The web application code is between the <APPLICATION> tags below"

<APPLICATION>
%s
</APPLICATION>


And the HTTP request is between the <REQUEST> tags below:

<REQUEST>
%s
</REQUEST>
`

type CodeInterpreterInterface interface {
	Interpret(req *models.Request, content *models.Content) (*models.LLMCodeExecution, error)
}

type CodeInterpreter struct {
	dbClient   database.DatabaseClient
	llmManager llm.LLMManagerInterface
	toolSet    *tools.CodeToolSet
}

// NewCodeInterpreter creates a new CodeSnippetEmulator.
func NewCodeInterpreter(llmManager llm.LLMManagerInterface, shellClient shell.ShellClientInterface, dbClient database.DatabaseClient) *CodeInterpreter {
	llmManager.SetResponseSchemaFromObject(InterOutput{}, "The code output")
	return &CodeInterpreter{
		llmManager: llmManager,
		dbClient:   dbClient,
		toolSet:    tools.NewCodeToolSet(shellClient),
	}
}

func (c *CodeInterpreter) Interpret(req *models.Request, content *models.Content) (*models.LLMCodeExecution, error) {
	tools := c.toolSet.BuildTools(req)

	res, err := c.llmManager.CompleteWithTools(
		[]llm.LLMMessage{
			{
				Role:    constants.LLMClientMessageSystem,
				Content: CodeInterpreterSystemPrompt,
			},
			{
				Role:    constants.LLMClientMessageUser,
				Content: fmt.Sprintf(ApplicationRequestTemplate, content.Data, req.Raw),
			},
		},
		tools,
		/* Do not cache the results. Note however that the tools themselves are free
		* to cache (and the shell emulator, for example, does this) */
		false,
	)

	if err != nil {
		return nil, fmt.Errorf("error completing prompt: %w", err)
	}

	result := &InterOutput{}
	if err = json.Unmarshal([]byte(util.RemoveJsonExpression(res.Output)), result); err != nil {
		slog.Error("error parsing json", slog.String("error", err.Error()), slog.String("json", res.Output))
		return nil, err
	}

	retVal := &models.LLMCodeExecution{
		Stdout:      []byte(result.Output),
		Headers:     result.Headers,
		RequestID:   req.ID,
		Snippet:     content.Data,
		SessionID:   req.SessionID,
		SourceModel: c.llmManager.LoadedModel(),
	}

	_, err = c.dbClient.Insert(retVal)
	if err != nil {
		slog.Error("error inserting llm code execution", slog.String("error", err.Error()))
		// On purpose we continue here and do not return. It's not the end of the
		// world if the database is not updated.
	}

	return retVal, nil
}
