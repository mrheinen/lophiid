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
package javascript

import "lophiid/pkg/util"

type Random struct {
	String RandomString `json:"string"`
}

type RandomString struct {
}

func (s RandomString) Alphanumeric(length int) string {
	return util.GenerateRandomAlphaNumericString(length)
}

func (s RandomString) Generate(length int, charset string) string {
	return util.GenerateRandomString(length, charset)
}
