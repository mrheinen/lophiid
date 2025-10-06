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
	"math/rand"
	"os"
	"reflect"
	"regexp"
	"strings"
	"unicode"
)

func GetStructName(m any) string {
	if t := reflect.TypeOf(m); t.Kind() == reflect.Ptr {
		return t.Elem().Name()
	} else {
		return t.Name()
	}
}

func ReadFileToString(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func IsValidUUID(uuid string) bool {
	pattern := "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	match, _ := regexp.MatchString(pattern, strings.ToLower(uuid))
	return match
}

// Checks if a string is ASCII.
func IsStringASCII(s string) bool {
	for _, c := range s {
		if c > unicode.MaxASCII {
			return false
		}
	}
	return true
}

const printableChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
const printableAlphaNumericChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func GenerateRandomString(length int, inputChars string) string {
	result := make([]byte, length)
	for i := range length {
		result[i] = inputChars[rand.Intn(len(inputChars))]
	}
	return string(result)
}

func GenerateRandomAlphaNumericString(length int) string {
	return GenerateRandomString(length, printableAlphaNumericChars)
}
