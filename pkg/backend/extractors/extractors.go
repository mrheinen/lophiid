package extractors

import (
	"encoding/hex"
	"html"
	"log/slog"
	"loophid/pkg/database"
	"net/url"
	"regexp"
	"strings"
)

type Extractor interface {
	MetaType() string
	ParseRequest(req *database.Request)
	ParseString(s string)
	GetMetadatas(requestID int64) []database.RequestMetadata
}


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
			res = append(res, decodeURLOrEmptyString(body, false))
		} else {
			for _, values := range params {
				for _, p := range values {
					res = append(res, decodeURLOrEmptyString(p, false))
				}
			}
		}
	} else {
		params, err := url.ParseQuery(string(req.Body))
		// Still try to parse as parameters.
		if err == nil && len(params) > 2 {
			for _, values := range params {
				for _, p := range values {
					res = append(res, decodeURLOrEmptyString(p, false))
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
		res = append(res, decodeURLOrEmptyString(req.Uri, true))
		return res
	}

	// TODO: Use req.Query here.
	query := req.Uri[qIdx+1:]
	path := req.Uri[:qIdx]

	res = append(res, decodeURLOrEmptyString(path, true))

	params, err := url.ParseQuery(query)

	if err != nil {
		slog.Debug("could not parse query", slog.String("error", err.Error()), slog.String("query", query))
		res = append(res, decodeURLOrEmptyString(query, true))
		return res
	}

	// In cases like /foo?payload the payload part is in the parameter name. In
	// that case we should add it.
	if len(params) == 1 {
		if _, ok := params[decodeURLOrEmptyString(query, true)]; ok {
			res = append(res, decodeURLOrEmptyString(query, true))
			return res
		}
	}

	for _, values := range params {
		for _, p := range values {
			res = append(res, decodeURLOrEmptyString(p, true))
		}
	}
	return res
}

func decodeURL(encoded string) (string, error) {
	if !strings.Contains(encoded, "%") {
		return encoded, nil
	}

	return url.QueryUnescape(encoded)
}

// roughDecodeURL is a fall back URL decoding function. The returned string will
// only have the ascii characters decoded. Anything else is left in tact.
func roughDecodeURL(encoded string) string {
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

// decodeURLOrEmptyString attempts to decode the string. It first uses the url
// package decoding which is strict but very complete. If that fails then it
// will fall back to a very simplistic search/replace decode function.
func decodeURLOrEmptyString(encoded string, removeSpace bool) string {
	// TODO: reconsider this hack.
	decoded := strings.ReplaceAll(encoded, ";", " ")

	if removeSpace {
		decoded = strings.ReplaceAll(decoded, "+", " ")
	}

	ret, err := decodeURL(decoded)
	if err != nil {
		slog.Warn("could not decode, falling back", slog.String("error", err.Error()))
		return roughDecodeURL(decoded)
	}
	return ret
}

func decodeHTML(encoded string) string {
	if strings.Contains(encoded, "&") {
		return html.UnescapeString(encoded)
	}
	return encoded
}