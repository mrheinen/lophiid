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
package util

import (
	"testing"
)

func TestVersionCompatibility(t *testing.T) {

	for _, test := range []struct {
		description string
		versionOne  string
		versionTwo  string
		expectError bool
	}{
		{
			description: "same version",
			versionOne:  "8.0.0",
			versionTwo:  "8.0.0",
			expectError: false,
		},
		{
			description: "different major version",
			versionOne:  "7.0.0",
			versionTwo:  "8.0.0",
			expectError: true,
		},
		{
			description: "different minor version",
			versionOne:  "7.0.0",
			versionTwo:  "7.1.0",
			expectError: true,
		},
		{
			description: "different patch version",
			versionOne:  "8.0.1",
			versionTwo:  "8.0.3",
			expectError: false,
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			err := IsLophiidVersionCompatible(test.versionOne, test.versionTwo)
			if err == nil && test.expectError {
				t.Errorf("Expected error but got none")
			} else if err != nil && !test.expectError {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
