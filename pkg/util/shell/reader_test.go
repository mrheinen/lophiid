package shell

import (
	"lophiid/pkg/util"
	"testing"
)

func TestFileIterator(t *testing.T) {

	for _, test := range []struct {
		description    string
		fileData       []byte
		numberOfIts    int
		expectedResult []string
	}{
		{
			description:    "simple file, newlines only",
			fileData:       []byte("a\nb\nc\nd\n"),
			numberOfIts:    4,
			expectedResult: []string{"a", "b", "c", "d"},
		},
		{
			description:    "simple file, no newline end",
			fileData:       []byte("a\nb\nc\nd"),
			numberOfIts:    4,
			expectedResult: []string{"a", "b", "c", "d"},
		},
		{
			description:    "simple file, no newline end, quoted ;",
			fileData:       []byte("a\nb=\"a;\"\nc\nd"),
			numberOfIts:    4,
			expectedResult: []string{"a", "b=\"a;\"", "c", "d"},
		},
		{
			description:    "simple file, open quote",
			fileData:       []byte("a\nb=\"a"),
			numberOfIts:    4,
			expectedResult: []string{"a", "b=\"a"},
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			fi := ScriptIterator{fileData: test.fileData}

			result := []string{}
			for i := 0; i < test.numberOfIts; i++ {
				data, hasMore := fi.Next()
				result = append(result, data)

				if !hasMore {
					break
				}
			}

			if !util.AreSlicesEqual(result, test.expectedResult) {
				t.Errorf("expected %v, got %v", test.expectedResult, result)
			}

		})
	}

}
