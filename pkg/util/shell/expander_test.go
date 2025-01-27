package shell

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpandVariables(t *testing.T) {

	exp := NewExpander()

	rdr := FileIterator{}
	rdr.fileData = []byte("AAAA=123\n$AAAA $AAAA")

	res := exp.Expand(&rdr)

	fmt.Printf("%s\n", res)

	if len(res) != 2 {
		t.Errorf("2, got %d", len(res))
	}

	if res[1] != "123 123" {
		t.Errorf("123 123, got %s", res[0])
	}
}

func TestExpandForLoop(t *testing.T) {

	for _, test := range []struct {
		description    string
		fileData       []byte
		expectedOutput []string
	}{
		{
			description: "simple for loop",
			fileData: []byte(`
for VARIABLE in 1 2 3 4 5
do
echo $VARIABLE
done`),

			expectedOutput: []string{"echo 1", "echo 2", "echo 3", "echo 4", "echo 5"},
		},
		{
			description: "for loop based on variable",
			fileData: []byte(`
VALS="1 2 3 4 5"
for VARIABLE in $VALS
do
echo $VARIABLE
done`),

			expectedOutput: []string{
				"VALS=\"1 2 3 4 5\"", "echo 1", "echo 2", "echo 3", "echo 4", "echo 5"},
		},
		{
			description: "for loop based on quoted variable",
			fileData: []byte(`
for VARIABLE in "aa bb cc"
do
echo $VARIABLE
done`),

			expectedOutput: []string{
				"echo aa", "echo bb", "echo cc"},
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			exp := NewExpander()
			rdr := FileIterator{}
			rdr.fileData = test.fileData

			res := exp.Expand(&rdr)

			assert.Equal(t, test.expectedOutput, res, "should be equal")

		})

	}
}
