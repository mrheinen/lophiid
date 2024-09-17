package extractors

import "testing"

func TestUnicodeExtractorFindAndAdd(t *testing.T) {

	for _, test := range []struct {
		description string
		input       string
		result      map[string]string
	}{
		{
			description: "empty input",
			input:       "",
			result:      map[string]string{},
		},
		{
			description: "find two strings",
			input:       `aaa \u0061 aa \u0062 aaa`,
			result: map[string]string{
				`\u0061`: "a",
				`\u0062`: "b",
			},
		},
		{
			description: "find one strings",
			input:       `\u0061\u0062\u0061\u0062\u0061\u0062`,
			result: map[string]string{
				`\u0061\u0062\u0061\u0062\u0061\u0062`: "ababab",
			},
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			result := make(map[string]string)
			ex := NewUnicodeExtractor(result, true)

			cnt := ex.FindAndAdd(test.input)
			if cnt != int64(len(test.result)) {
				t.Errorf("expected %d result, got %d", len(test.result), cnt)
			}

			for k, v := range test.result {

				val, ok := result[k]
				if !ok {
					t.Errorf("expected result %s", k)
					continue
				}

				if val != v {
					t.Errorf("expected %s, got %s", v, val)

				}

			}
		})
	}
}
