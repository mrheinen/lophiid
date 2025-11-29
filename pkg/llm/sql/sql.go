package sql

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
)

const SqlInjectionSystemPrompt = `
You are a SQL database emulator. Your task is to simulate the response to a SQL injection attempt.
You need to analyze the provided SQL injection and determine:
1. The output of the SQL query (if any).
2. Whether it is a blind SQL injection.
3. If the attacker expects a delay (e.g. using SLEEP(), BENCHMARK(), pg_sleep(), etc.), determine the expected delay in milliseconds.

If the injection expects a delay, you should specify the delay in milliseconds. If not, set the delay to 0.
If the injection is a blind SQL injection, set is_blind to true.
Provide the output of the query in the "output" field. If there is no output (e.g. purely timing based or error based but no data returned), leave it empty or provide an error message if appropriate.
`

type SqlInjectionOutput struct {
	Output  string `json:"output" jsonschema_description:"The output of the SQL query"`
	IsBlind bool   `json:"is_blind" jsonschema_description:"Whether this is a blind SQL injection"`
	DelayMs int    `json:"delay_ms" jsonschema_description:"The expected delay in milliseconds"`
}

type SqlInjectionEmulatorInterface interface {
	Emulate(req *models.Request, payload string) (*SqlInjectionOutput, error)
}

type FakeSqlInjectionEmulator struct {
	OutputToReturn *SqlInjectionOutput
	ErrorToReturn  error
}

func (f *FakeSqlInjectionEmulator) Emulate(req *models.Request, payload string) (*SqlInjectionOutput, error) {
	return f.OutputToReturn, f.ErrorToReturn
}

type SqlInjectionEmulator struct {
	llmManager llm.LLMManagerInterface
}

func NewSqlInjectionEmulator(llmManager llm.LLMManagerInterface) *SqlInjectionEmulator {
	llmManager.SetResponseSchemaFromObject(SqlInjectionOutput{}, "The SQL injection result")
	return &SqlInjectionEmulator{
		llmManager: llmManager,
	}
}

func (s *SqlInjectionEmulator) Emulate(req *models.Request, payload string) (*SqlInjectionOutput, error) {
	res, err := s.llmManager.CompleteWithMessages(
		[]llm.LLMMessage{
			{
				Role:    constants.LLMClientMessageSystem,
				Content: SqlInjectionSystemPrompt,
			},
			{
				Role:    constants.LLMClientMessageUser,
				Content: fmt.Sprintf("The SQL injection payload is: %s", payload),
			},
		},
		true,
	)

	if err != nil {
		return nil, fmt.Errorf("error completing prompt: %w", err)
	}

	result := &SqlInjectionOutput{}
	if err = json.Unmarshal([]byte(util.RemoveJsonExpression(res.Output)), result); err != nil {
		slog.Error("error parsing json", slog.String("error", err.Error()), slog.String("json", res.Output))
		return nil, err
	}

	return result, nil
}
