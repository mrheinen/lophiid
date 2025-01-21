// Lophiid distributed honeypot
// Copyright (C) 2025 Niels Heinen
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
package templator

import (
	"bytes"
	"testing"
)

func TestRenderTemplateString(t *testing.T) {
	tmpr := NewTemplator()
	if tmpr == nil {
		t.Fatal("failed to get templator")
	}

	tmp, err := tmpr.RenderTemplate([]byte("%%STRING%%A%%5%%"))
	if err != nil {
		t.Fatal("failed to render template")
	}

	if !bytes.Equal(tmp, []byte("AAAAA")) {
		t.Errorf("expected \"AAAAA\", got \"%s\"", tmp)
	}

	tmp2, err := tmpr.RenderTemplate([]byte("%%STRING%%0-9AB%%10%%"))
	if err != nil {
		t.Fatal("failed to render template")
	}

	for _, c := range tmp2 {
		if (c < '0' || c > '9') && c != 'B' && c != 'A' {
			t.Errorf("expected only 0-9A-B, got %c", c)
		}
	}
}
