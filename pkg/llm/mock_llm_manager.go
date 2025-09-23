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
package llm

// MockLLMManager implements LLMManagerInterface for testing
type MockLLMManager struct {
	CompletionToReturn   string
	ErrorToReturn        error
	LastReceivedMessages []LLMMessage
}

func (m *MockLLMManager) Complete(prompt string, cacheResult bool) (string, error) {
	return m.CompletionToReturn, m.ErrorToReturn
}

func (m *MockLLMManager) CompleteMultiple(prompts []string, cacheResult bool) (map[string]string, error) {
	result := make(map[string]string)
	for _, prompt := range prompts {
		result[prompt] = m.CompletionToReturn
	}
	return result, m.ErrorToReturn
}

func (m *MockLLMManager) CompleteWithMessages(msgs []LLMMessage) (string, error) {
	m.LastReceivedMessages = msgs
	return m.CompletionToReturn, m.ErrorToReturn
}

func (m *MockLLMManager) SetResponseSchemaFromObject(obj any, title string) {
	// No-op for testing
}

func (m *MockLLMManager) LoadedModel() string {
	return "test-model"
}
