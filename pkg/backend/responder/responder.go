package responder

type Responder interface {
	Respond(resType string, promptInput string, template string) (string, error)
}

const LLMReplacementFallbackString = ""

type FakeResponder struct {
	TemplateToReturn string
	ErrorToReturn    error
	LastPromptInput  string
}

func (l *FakeResponder) Respond(resType string, promptInput string, template string) (string, error) {
	l.LastPromptInput = promptInput
	return l.TemplateToReturn, l.ErrorToReturn
}
