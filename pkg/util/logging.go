package util

import (
	"io"
)

// NewTeeLogWriter returns a TeeLogWriter that will write to all outputs given.
func NewTeeLogWriter(outputs []io.Writer) *TeeLogWriter {
	return &TeeLogWriter{
		outputs,
	}
}

type TeeLogWriter struct {
	outputs []io.Writer
}

func (t *TeeLogWriter) Write(p []byte) (n int, err error) {
	for _, w := range t.outputs {
		n, err = w.Write(p)
		if err != nil {
			return n, err
		}
	}
	return n, err
}
