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
package shell

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
)

type ShellClient struct {
	llmManager llm.LLMManagerInterface
	dbClient   database.DatabaseClient
}

type CommandOutput struct {
	CommandOutput string `json:"command_output"`
	Hostname      string `json:"hostname"`
	WorkingDir    string `json:"working_directory"`
	Username      string `json:"username"`
}

const MaxPreviousCommandsToFetch = 20

const initialPrompt = `
You are a Linux console/terminal. The user will give you linux commands and you are to give example/fake output without any other comments or analysis.

I also want you to provide me with a fake , short, hostname (e.g. db-001, backend, vpn-uk-001, etc), a good working directory (e.g. /root, /<username>/, /var/www/, etc) and a realistic username (root, postgres, www-data, etc) that will be used in this request (if necessary) and future requests for command output.
`

const nextPrompt = `
You are a Linux console/terminal that can be given a command (or multiple commands) and who then provides an example/fake output. When giving example output, please take into account previous commands that have been send by the user and the output you previously generated for them. For example, if a previous command was to create a directory and the new command is to list all directories then I expect you to list the new directory as well.

Take into account the following environment variables:

CWD=%s
USER=%s
HOSTNAME=%s
`

type LLMCommandOutput struct {
	CommandOutput string `json:"command_output" jsonschema_description:"A string that contains the output of the command (fake but realistic)"`
	Hostname      string `json:"hostname" jsonschema_description:"The hostname for the system the command ran on"`
	WorkingDir    string `json:"working_directory" jsonschema_description:"The working directory for the command"`
	Username      string `json:"username" jsonschema_description:"The username for the command"`
}

func NewShellClient(llmManager llm.LLMManagerInterface, dbClient database.DatabaseClient) *ShellClient {
	llmManager.SetResponseSchemaFromObject(LLMCommandOutput{}, "The command output and environment variables")
	return &ShellClient{
		llmManager: llmManager,
		dbClient:   dbClient,
	}
}

func (s *ShellClient) StoreCommandOutput(cmdOutput CommandOutput, req *models.Request, cmd string) (*models.SessionExecutionContext, error) {
	ins := &models.SessionExecutionContext{
		SessionID:   req.SessionID,
		RequestID:   req.ID,
		EnvHostname: cmdOutput.Hostname,
		EnvCWD:      cmdOutput.WorkingDir,
		EnvUser:     cmdOutput.Username,
		Input:       cmd,
		Output:      cmdOutput.CommandOutput,
	}

	_, err := s.dbClient.Insert(ins)

	if err != nil {
		return nil, err
	}

	return ins, nil
}

func (s *ShellClient) RunCommand(req *models.Request, cmd string) (*models.SessionExecutionContext, error) {

	// If this is the first command in the chain, just run it with the initial
	// prompt.
	var result CommandOutput

	previousCmds, err := s.dbClient.SearchSessionExecutionContext(0, MaxPreviousCommandsToFetch, fmt.Sprintf("session_id:%d", req.SessionID))
	if err != nil {
		fmt.Println("error searching database", err)
	}

	var msgs []llm.LLMMessage

	if err != nil || len(previousCmds) == 0 {
		// Single prompt with system message.
		msgs = []llm.LLMMessage{
			{
				Role:    constants.LLMClientMessageSystem,
				Content: initialPrompt,
			},
			{
				Role:    constants.LLMClientMessageUser,
				Content: cmd,
			},
		}
	} else {

		tmp := make([]models.SessionExecutionContext, len(previousCmds))
		for i := range previousCmds {
			tmp[len(tmp)-i-1] = previousCmds[i]
		}

		previousCmds = tmp

		lastCmd := previousCmds[len(previousCmds)-1]
		msgs = []llm.LLMMessage{
			{
				Role:    constants.LLMClientMessageSystem,
				Content: fmt.Sprintf(nextPrompt, lastCmd.EnvCWD, lastCmd.EnvUser, lastCmd.EnvHostname),
			},
		}

		for _, pCmd := range previousCmds {
			msgs = append(msgs, llm.LLMMessage{
				Role:    constants.LLMClientMessageUser,
				Content: pCmd.Input,
			})

			msgs = append(msgs, llm.LLMMessage{
				Role:    constants.LLMClientMessageAssistant,
				Content: pCmd.Output,
			})
		}

		msgs = append(msgs, llm.LLMMessage{
			Role:    constants.LLMClientMessageUser,
			Content: cmd,
		})
	}

	res, err := s.llmManager.CompleteWithMessages(msgs)

	if err != nil {
		slog.Error("error running command", slog.String("error", err.Error()), slog.String("command", cmd))
		return nil, err
	}

	if err := json.Unmarshal([]byte(util.RemoveJsonExpression(res)), &result); err != nil {
		slog.Error("error parsing json", slog.String("error", err.Error()), slog.String("json", res))
		return nil, err
	}

	return s.StoreCommandOutput(result, req, cmd)
}
