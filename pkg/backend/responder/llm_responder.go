package responder

import (
	"fmt"
	"lophiid/pkg/llm"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"strings"
)

type LLMResponder struct {
	llmManager    *llm.LLMManager
	maxInputChars int
}

func NewLLMResponder(llmManager *llm.LLMManager, maxInputChars int) *LLMResponder {
	return &LLMResponder{
		llmManager:    llmManager,
		maxInputChars: maxInputChars,
	}
}

func (l *LLMResponder) Respond(resType string, promptInput string, template string) (string, error) {
	if len(promptInput) > l.maxInputChars {
		return "", fmt.Errorf("input too long (size: %d)", len(promptInput))
	}

	// First make sure there actually is a replacement tag. If the tag is missing
	// then we will append one to the end of the template.
	if !strings.Contains(template, LLMReplacementTag) {
		template = fmt.Sprintf("%s\n%s", template, LLMReplacementTag)
	}

	var basePrompt string
	switch resType {
	case constants.ResponderTypeCommandInjection:
		basePrompt = commandInjectionPrompt
	case constants.ResponderTypeSourceCodeExecution:
		basePrompt = sourceCodeExecutionPrompt

	default:
		return "", fmt.Errorf("invalid responder type: %s", resType)
	}

	deli := util.GenerateRandomAlphaNumericString(20)
	finalPrompt := fmt.Sprintf(basePrompt, deli, deli, promptInput)
	res, err := l.llmManager.Complete(finalPrompt)
	if err != nil {
		return strings.Replace(template, LLMReplacementTag, LLMReplacementFallbackString, 1), err
	}

	return strings.Replace(template, LLMReplacementTag, res, 1), nil
}
