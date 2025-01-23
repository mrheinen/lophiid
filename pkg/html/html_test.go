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
package html

import (
	"testing"
)

func TestMakeURLsRelative(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		tagAttrs []TagAttribute
		targetIP string
		want     string
		wantErr  bool
	}{
		{
			name:     "img tag with matching IP",
			input:    `<img src="https://192.168.1.1/image.jpg" alt="test">`,
			tagAttrs: DefaultTagAttributes(),
			targetIP: "192.168.1.1",
			want:     `<img src="/image.jpg" alt="test">`,
			wantErr:  false,
		},
		{
			name:     "img tag with non-matching IP",
			input:    `<img src="https://192.168.1.2/image.jpg" alt="test">`,
			tagAttrs: DefaultTagAttributes(),
			targetIP: "192.168.1.1",
			want:     `<img src="https://192.168.1.2/image.jpg" alt="test">`,
			wantErr:  false,
		},
		{
			name:     "img tag with multiple attributes",
			input:    `<img foo="bar" src="https://192.168.1.1/image.jpg" alt="test">`,
			tagAttrs: DefaultTagAttributes(),
			targetIP: "192.168.1.1",
			want:     `<img foo="bar" src="/image.jpg" alt="test">`,
			wantErr:  false,
		},
		{
			name:     "script tag with single quotes",
			input:    `<script src='http://192.168.1.1/script.js'></script>`,
			tagAttrs: DefaultTagAttributes(),
			targetIP: "192.168.1.1",
			want:     `<script src='/script.js'></script>`,
			wantErr:  false,
		},
		{
			name:     "multiple tags with mixed IPs",
			input:    `<img src="https://192.168.1.1/image.jpg"><script src="http://192.168.1.2/script.js">`,
			tagAttrs: DefaultTagAttributes(),
			targetIP: "192.168.1.1",
			want:     `<img src="/image.jpg"><script src="http://192.168.1.2/script.js">`,
			wantErr:  false,
		},
		{
			name:     "already relative urls",
			input:    `<img src="/image.jpg"><script src="script.js">`,
			tagAttrs: DefaultTagAttributes(),
			targetIP: "192.168.1.1",
			want:     `<img src="/image.jpg"><script src="script.js">`,
			wantErr:  false,
		},
		{
			name:     "custom tag attribute",
			input:    `<foo src="https://192.168.1.1/resource">`,
			tagAttrs: []TagAttribute{{Tag: "foo", Attribute: "src"}},
			targetIP: "192.168.1.1",
			want:     `<foo src="/resource">`,
			wantErr:  false,
		},
		{
			name:     "url with query parameters",
			input:    `<img src="https://192.168.1.1/image.jpg?size=large&format=png">`,
			tagAttrs: DefaultTagAttributes(),
			targetIP: "192.168.1.1",
			want:     `<img src="/image.jpg?size=large&format=png">`,
			wantErr:  false,
		},
		{
			name:     "url with fragment",
			input:    `<img src="https://192.168.1.1/image.jpg#section1">`,
			tagAttrs: DefaultTagAttributes(),
			targetIP: "192.168.1.1",
			want:     `<img src="/image.jpg#section1">`,
			wantErr:  false,
		},
		{
			name:     "url with port number",
			input:    `<img src="https://192.168.1.1:8080/image.jpg">`,
			tagAttrs: DefaultTagAttributes(),
			targetIP: "192.168.1.1:8080",
			want:     `<img src="/image.jpg">`,
			wantErr:  false,
		},
		{
			name:     "invalid url",
			input:    `<img src="http://[invalid-ip]/image.jpg">`,
			tagAttrs: DefaultTagAttributes(),
			targetIP: "192.168.1.1",
			want:     `<img src="http://[invalid-ip]/image.jpg">`,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MakeURLsRelative([]byte(tt.input), tt.tagAttrs, tt.targetIP)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeURLsRelative() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if string(got) != tt.want {
				t.Errorf("MakeURLsRelative() = %v, want %v", string(got), tt.want)
			}
		})
	}
}
