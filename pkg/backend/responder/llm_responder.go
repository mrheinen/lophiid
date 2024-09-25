package responder

import (
	"fmt"
	"lophiid/pkg/llm"
	"lophiid/pkg/util/constants"
	"strings"
)

type LLMResponder struct {
	llmManager *llm.LLMManager
}

func NewLLMResponder(llmManager *llm.LLMManager) *LLMResponder {
	return &LLMResponder{llmManager: llmManager}
}

func (l *LLMResponder) Respond(resType string, promptInput string, template string) (string, error) {
	// First make sure there actually is a replacement tag. If the tag is missing
	// then we will append one to the end of the template.
	if !strings.Contains(template, LLMReplacementTag) {
		template = fmt.Sprintf("%s\n%s", template, LLMReplacementTag)
	}

	var basePrompt string
	switch resType {
	case constants.ResponderTypeCommandInjection:
		basePrompt = commandInjectionPrompt

	default:
		return "", fmt.Errorf("invalid responder type: %s", resType)
	}

	res, err := l.llmManager.Complete(fmt.Sprintf(basePrompt, promptInput))
	if err != nil {
		return strings.Replace(template, LLMReplacementTag, LLMReplacementFallbackString, 1), err
	}

	return strings.Replace(template, LLMReplacementTag, res, 1), nil
}
