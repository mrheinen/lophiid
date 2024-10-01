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
package decoding

import (
	"encoding/hex"
	"html"
	"log/slog"
	"lophiid/pkg/database"
	"net/url"
	"regexp"
	"strings"
)

// StringsFromRequest function will iterate over the request and collect strings
// from varies HTTP fields. It will also decode and parse data where necessary
// so that only strings of interest for finding metadata are returned. E.g.
// strings in a value of a parameter and not the parameter name itself.
func StringsFromRequest(req *database.Request) []string {
	var res []string
	// TODO: Make this cleaner and access the actual
	// header instead of grepping the entire request.
	if strings.Contains(req.Raw, "application/x-www-form-urlencoded") {
		body := string(req.Body)
		params, err := url.ParseQuery(body)
		if err != nil || !isFormUrlEncoded(body) {
			res = append(res, DecodeURLOrEmptyString(body, false))
		} else {
			for _, values := range params {
				for _, p := range values {
					res = append(res, DecodeURLOrEmptyString(p, false))
				}
			}
		}
	} else {
		params, err := url.ParseQuery(string(req.Body))
		// Still try to parse as parameters.
		if err == nil && len(params) > 2 {
			for _, values := range params {
				for _, p := range values {
					res = append(res, DecodeURLOrEmptyString(p, false))
				}
			}
		} else {
			res = append(res, string(req.Body))
		}
	}

	// Avoid proxy requests
	if strings.HasPrefix(req.Uri, "http") {
		return res
	}

	qIdx := strings.Index(req.Uri, "?")
	if qIdx == -1 {
		res = append(res, DecodeURLOrEmptyString(req.Uri, true))
		return res
	}

	// TODO: Use req.Query here.
	query := req.Uri[qIdx+1:]
	path := req.Uri[:qIdx]

	res = append(res, DecodeURLOrEmptyString(path, true))

	params, err := url.ParseQuery(query)

	if err != nil {
		slog.Debug("could not parse query", slog.String("error", err.Error()), slog.String("query", query))
		res = append(res, DecodeURLOrEmptyString(query, true))
		return res
	}

	// In cases like /foo?payload the payload part is in the parameter name. In
	// that case we should add it.
	if len(params) == 1 {
		if _, ok := params[DecodeURLOrEmptyString(query, true)]; ok {
			res = append(res, DecodeURLOrEmptyString(query, true))
			return res
		}
	}

	for _, values := range params {
		for _, p := range values {
			res = append(res, DecodeURLOrEmptyString(p, true))
		}
	}
	return res
}

func DecodeURL(encoded string) (string, error) {
	if !strings.Contains(encoded, "%") {
		return encoded, nil
	}

	return url.QueryUnescape(encoded)
}

// RoughDecodeURL is a fall back URL decoding function. The returned string will
// only have the ascii characters decoded. Anything else is left in tact.
func RoughDecodeURL(encoded string) string {
	var ret strings.Builder
	ret.Grow(len(encoded))
	for i := 0; i < len(encoded); {
		if encoded[i] != '%' || i > len(encoded)-3 {
			ret.WriteByte(encoded[i])
			i += 1
			continue
		} else {
			dst := make([]byte, 1)
			bytesWritten, err := hex.Decode(dst, []byte{encoded[i+1], encoded[i+2]})
			if bytesWritten == 1 && err == nil && dst[0] > 32 && dst[0] < 177 {
				ret.WriteByte(dst[0])
			} else {
				ret.WriteByte(encoded[i])
				ret.WriteByte(encoded[i+1])
				ret.WriteByte(encoded[i+2])
			}
			i = i + 3
		}
	}
	return ret.String()
}

// isFormUrlEncoded purpose is to determine whether a body string is a URL
// encoded form or not.
func isFormUrlEncoded(body string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9_]+=`).MatchString(body)
}

// DecodeURLOrEmptyString attempts to decode the string. It first uses the url
// package decoding which is strict but very complete. If that fails then it
// will fall back to a very simplistic search/replace decode function.
func DecodeURLOrEmptyString(encoded string, removeSpace bool) string {
	if removeSpace {
		encoded = strings.ReplaceAll(encoded, "+", " ")
	}

	ret, err := DecodeURL(encoded)
	if err != nil {
		slog.Warn("could not decode, falling back", slog.String("error", err.Error()))
		return RoughDecodeURL(encoded)
	}
	return ret
}

func DecodeHTML(encoded string) string {
	if strings.Contains(encoded, "&") {
		return html.UnescapeString(encoded)
	}
	return encoded
}
