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

package file

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
)

const FileAccessSystemPrompt = `
You are a file system emulator. Your task is to provide the content of a specific file requested by a user.
You should provide realistic content for common files (like /etc/passwd, /etc/hosts, configuration files, etc.).
If the file is unknown or you cannot determine its content, provide a reasonable placeholder or empty content, but try to be helpful to the attacker (honeypot behavior).

Only provide the content of the file, nothing else.
Make sure you follow the requested JSON format for your output and put the content in the "content" field.
`

type FileOutput struct {
	Content string `json:"content" jsonschema_description:"The content of the file"`
}

type FileAccessEmulatorInterface interface {
	Emulate(req *models.Request, filename string) (string, error)
}

type FakeFileAccessEmulator struct {
	ContentToReturn string
	ErrorToReturn   error
}

func (f *FakeFileAccessEmulator) Emulate(req *models.Request, filename string) (string, error) {
	return f.ContentToReturn, f.ErrorToReturn
}

type FileAccessEmulator struct {
	llmManager llm.LLMManagerInterface
}

func NewFileAccessEmulator(llmManager llm.LLMManagerInterface) *FileAccessEmulator {
	llmManager.SetResponseSchemaFromObject(FileOutput{}, "The file content")
	return &FileAccessEmulator{
		llmManager: llmManager,
	}
}

func (f *FileAccessEmulator) Emulate(req *models.Request, filename string) (string, error) {

	res, err := f.llmManager.CompleteWithMessages(
		[]llm.LLMMessage{
			{
				Role:    constants.LLMClientMessageSystem,
				Content: FileAccessSystemPrompt,
			},
			{
				Role:    constants.LLMClientMessageUser,
				Content: fmt.Sprintf("The file requested is: %s", filename),
			},
		},
		true,
	)

	if err != nil {
		return "", fmt.Errorf("error completing prompt: %w", err)
	}

	result := &FileOutput{}
	if err = json.Unmarshal([]byte(util.RemoveJsonExpression(res.Output)), result); err != nil {
		slog.Error("error parsing json", slog.String("error", err.Error()), slog.String("json", res.Output))
		return "", err
	}

	return result.Content, nil
}
