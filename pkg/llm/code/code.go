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

package code

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

type CodeOutput struct {
	Stdout   string `json:"stdout" jsonschema_description:"The stdout output of the code"`
	Headers  string `json:"headers" jsonschema_description:"HTTP headers output of the code"`
	Language string `json:"language" jsonschema_description:"The language of the code"`
}

const CodeEmulationSystemPrompt = `
You are given a code snippet and your task is to determine what the output of the snippet would be if it were successfully executed. You do not need to execute it yourself. Instead your knowledge of programming languages is used to determine the output. Keep in mind that this will likely not be a complete program and just a snippet. Just focus on the snippet and try to determine/estimate what output it would generate if properly executed as part of a larger program.

Make sure you follow the requested JSON format for your output. The json output can have the following fields:

"stdout": This should contain the output of the code. When determining what this output will be, assume that all operations in the snippet I gave you are successful. Use an empty string if there is no output.
"headers": If the code outputs HTTP headers then I want you to store them in this field:  each "header: value" pair should be on their own line. Leave empty otherwise.
"language": The language of the code (e.g. c, java, c++, python, golang, rust, perl, ruby, php, etc). Use "unknown" if you do not recognize the language.
`

type CodeSnippetEmulatorInterface interface {
	Emulate(req *models.Request, code string) (*models.LLMCodeExecution, error)
}

type FakeCodeSnippetEmulator struct {
	ErrorToReturn  error
	ResultToReturn *models.LLMCodeExecution
}

func (f *FakeCodeSnippetEmulator) Emulate(req *models.Request, code string) (*models.LLMCodeExecution, error) {
	return f.ResultToReturn, f.ErrorToReturn
}

type CodeSnippetEmulator struct {
	dbClient    database.DatabaseClient
	llmManager  llm.LLMManagerInterface
	toolSet     *tools.CodeToolSet
}

// NewCodeSnippetEmulator creates a new CodeSnippetEmulator.
func NewCodeSnippetEmulator(llmManager llm.LLMManagerInterface, shellClient shell.ShellClientInterface, dbClient database.DatabaseClient) *CodeSnippetEmulator {
	llmManager.SetResponseSchemaFromObject(CodeOutput{}, "The code output")
	return &CodeSnippetEmulator{
		llmManager:  llmManager,
		dbClient:    dbClient,
		toolSet:     tools.NewCodeToolSet(shellClient),
	}
}


func (c *CodeSnippetEmulator) Emulate(req *models.Request, code string) (*models.LLMCodeExecution, error) {
	tools := c.toolSet.BuildTools(req)

	res, err := c.llmManager.CompleteWithTools(
		[]llm.LLMMessage{
			{
				Role:    constants.LLMClientMessageSystem,
				Content: CodeEmulationSystemPrompt,
			},
			{
				Role:    constants.LLMClientMessageUser,
				Content: code,
			},
		},
		tools,
		true,
	)

	if err != nil {
		return nil, fmt.Errorf("error completing prompt: %w", err)
	}

	result := &CodeOutput{}
	if err = json.Unmarshal([]byte(util.RemoveJsonExpression(res.Output)), result); err != nil {
		slog.Error("error parsing json", slog.String("error", err.Error()), slog.String("json", res.Output))
		return nil, err
	}

	retVal := models.LLMCodeExecution{
		Stdout:      []byte(result.Stdout),
		Headers:     result.Headers,
		Language:    result.Language,
		Snippet:     []byte(code),
		RequestID:   req.ID,
		SessionID:   req.SessionID,
		SourceModel: c.llmManager.LoadedModel(),
	}

	_, err = c.dbClient.Insert(&retVal)
	if err != nil {
		slog.Error("error inserting llm code execution", slog.String("error", err.Error()))
		// On purpose we continue here and do not return. It's not the end of the
		// world if the database is not updated.
	}

	return &retVal, nil
}
