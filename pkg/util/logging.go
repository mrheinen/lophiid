// Lophiid distributed honeypot
// Copyright (C) 2024 Niels Heinen
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
//
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
