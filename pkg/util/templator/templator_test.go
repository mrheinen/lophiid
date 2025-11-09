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
	"lophiid/pkg/database/models"
	"strconv"
	"testing"
)

func TestRenderTemplateString(t *testing.T) {
	tmpr := NewTemplator()
	if tmpr == nil {
		t.Fatal("failed to get templator")
	}

	fakeReq := &models.Request{}

	tmp, err := tmpr.RenderTemplate(fakeReq, []byte("%%STRING%%A%%5%%"))
	if err != nil {
		t.Fatal("failed to render template")
	}

	if !bytes.Equal(tmp, []byte("AAAAA")) {
		t.Errorf("expected \"AAAAA\", got \"%s\"", tmp)
	}

	tmp2, err := tmpr.RenderTemplate(fakeReq, []byte("%%STRING%%0-9AB%%10%%"))
	if err != nil {
		t.Fatal("failed to render template")
	}

	for _, c := range tmp2 {
		if (c < '0' || c > '9') && c != 'B' && c != 'A' {
			t.Errorf("expected only 0-9A-B, got %c", c)
		}
	}
}

func TestRenderTemplateRequestValues(t *testing.T) {
	tmpr := NewTemplator()
	if tmpr == nil {
		t.Fatal("failed to get templator")
	}

	fakeReq := &models.Request{
		SourceIP:   "1.1.1.1",
		HoneypotIP: "2.2.2.2",
		SourcePort: int64(18080),
		Port:       int64(8080),
	}

	for _, test := range []struct {
		description    string
		macro          string
		expectedResult string
	}{
		{
			description:    "source ip",
			macro:          "%%REQUEST_SOURCE_IP%%",
			expectedResult: fakeReq.SourceIP,
		},
		{
			description:    "honeypot ip",
			macro:          "%%REQUEST_HONEYPOT_IP%%",
			expectedResult: fakeReq.HoneypotIP,
		},
		{
			description:    "source port",
			macro:          "%%REQUEST_SOURCE_PORT%%",
			expectedResult: strconv.FormatInt(fakeReq.SourcePort, 10),
		},
		{
			description:    "port",
			macro:          "%%REQUEST_PORT%%",
			expectedResult: strconv.FormatInt(fakeReq.Port, 10),
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			tmp, err := tmpr.RenderTemplate(fakeReq, []byte(test.macro))
			if err != nil {
				t.Fatal("failed to render template")
			}
			if !bytes.Equal(tmp, []byte(test.expectedResult)) {
				t.Errorf("expected \"%s\", got \"%s\"", test.expectedResult, tmp)
			}
		})
	}
}
