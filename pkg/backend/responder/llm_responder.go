package responder

import (
	"fmt"
	"log/slog"
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
		slog.Error("input too long", slog.Int("size", len(promptInput)))
		return "", fmt.Errorf("input too long (size: %d)", len(promptInput))
	}

	// First make sure there actually is a replacement tag. If the tag is missing
	// then we will append one to the end of the template.
	if !strings.Contains(template, LLMReplacementTag) {
		template = fmt.Sprintf("%s\n%s", template, LLMReplacementTag)
	}

	var basePrompt string
	res := ""
	var err error
	switch resType {
	case constants.ResponderTypeCommandInjection:
		basePrompt = commandInjectionPrompt
		for _, pInput := range util.SplitCommandsOnSemi(promptInput) {
			finalPrompt := fmt.Sprintf(basePrompt, pInput)
			tmpRes, err := l.llmManager.Complete(finalPrompt)
			if err != nil {
				slog.Error("could not complete LLM request", slog.String("error", err.Error()))
				return strings.Replace(template, LLMReplacementTag, LLMReplacementFallbackString, 1), err
			}

			res += tmpRes
		}

	case constants.ResponderTypeSourceCodeExecution:
		basePrompt = sourceCodeExecutionPrompt
		finalPrompt := fmt.Sprintf(basePrompt, promptInput)
		res, err = l.llmManager.Complete(finalPrompt)
		if err != nil {
			slog.Error("could not complete LLM request", slog.String("error", err.Error()))
			return strings.Replace(template, LLMReplacementTag, LLMReplacementFallbackString, 1), err
		}

	default:
		slog.Error("invalid responder type", slog.String("type", resType))
		return "", fmt.Errorf("invalid responder type: %s", resType)
	}

	return strings.Replace(template, LLMReplacementTag, res, 1), nil
}
