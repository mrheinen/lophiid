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

package tools

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"lophiid/pkg/llm/shell"
)

type CodeToolSet struct {
	shellClient shell.ShellClientInterface
}

func NewCodeToolSet(shellClient shell.ShellClientInterface) *CodeToolSet {
	return &CodeToolSet{
		shellClient: shellClient,
	}
}

// StringToMD5 calculates the MD5 checksum of a string
func (t *CodeToolSet) StringToMD5(input string) (string, error) {
	hash := md5.Sum([]byte(input))
	return hex.EncodeToString(hash[:]), nil
}

// StringFromBase64 decodes a base64 encoded string
func (t *CodeToolSet) StringFromBase64(input string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return "", fmt.Errorf("error decoding base64: %w", err)
	}
	return string(decoded), nil
}

func (t *CodeToolSet) ShellCommandToOutput(req *models.Request, input string) (string, error) {
	if t.shellClient == nil {
		return "", fmt.Errorf("shell client not configured")
	}

	result, err := t.shellClient.RunCommand(req, input)
	if err != nil {
		return "", fmt.Errorf("error running command: %w", err)
	}
	return result.Output, nil
}

func ParseToolInput(args string) (string, error) {
	var params struct {
		Input string `json:"input"`
	}

	if err := json.Unmarshal([]byte(args), &params); err != nil {
		return "", fmt.Errorf("error parsing arguments: %w", err)
	}

	return params.Input, nil
}

func (t *CodeToolSet) BuildTools(req *models.Request) []llm.LLMTool {
	tools := []llm.LLMTool{
		{
			Name:        "string_to_md5",
			Description: "Calculate the MD5 checksum of a string. Use this whenever you need to compute an MD5 hash of a string value.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"input": map[string]any{
						"type":        "string",
						"description": "The string to calculate the MD5 checksum for",
					},
				},
				"required": []string{"input"},
			},
			Function: func(args string) (string, error) {
				input, err := ParseToolInput(args)
				if err != nil {
					return "", err
				}
				return t.StringToMD5(input)
			},
		},
		{
			Name:        "string_from_base64",
			Description: "Decode a base64 encoded string. Use this whenever you need to decode a base64 string value.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"input": map[string]any{
						"type":        "string",
						"description": "The base64 encoded string to decode",
					},
				},
				"required": []string{"input"},
			},
			Function: func(args string) (string, error) {
				input, err := ParseToolInput(args)
				if err != nil {
					return "", err
				}
				return t.StringFromBase64(input)
			},
		},
	}

	if t.shellClient != nil {
		tools = append(tools, llm.LLMTool{
			Name:        "shell_command_to_output",
			Description: "Turns shell commands into its output. Use this whenever you need the output of a shell command (or multiple commands at once)",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"input": map[string]any{
						"type":        "string",
						"description": "The shell command. Can be multiple commands at once.",
					},
				},
				"required": []string{"input"},
			},
			Function: func(args string) (string, error) {
				input, err := ParseToolInput(args)
				if err != nil {
					return "", err
				}
				return t.ShellCommandToOutput(req, input)
			},
		})
	}

	return tools
}
