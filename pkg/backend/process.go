package backend

import (
	"encoding/base64"
	"html"
	"log/slog"
	"loophid/pkg/database"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	xurls "mvdan.cc/xurls/v2"
)

var (
	base64Reg    = regexp.MustCompile(`([a-zA-Z0-9=/+]*)`)
	urlStrictReg = xurls.Strict()
)

func decodeURL(encoded string) (string, error) {
	if !strings.Contains(encoded, "%") {
		return encoded, nil
	}

	// This is a special case and in preparation of the Base64 encoding we do
	// later on. We may have to rethink whether to keep this here or move it
	// somewhere else.  Anyway, a + in the URL is a space.
	decoded := strings.ReplaceAll(encoded, "+", " ")
	return url.QueryUnescape(decoded)
}

func decodeURLOrEmptyString(encoded string) string {
	ret, err := decodeURL(encoded)
	if err != nil {
		return ""
	}
	return ret
}

func decodeHTML(encoded string) string {
	if strings.Contains(encoded, "&") {
		return html.UnescapeString(encoded)
	}
	return encoded
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
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
		params, err := url.ParseQuery(string(req.Body))
		if err != nil {
			slog.Warn("could not parse body", slog.String("error", err.Error()),
				slog.String("body", string(req.Body)))
			res = append(res, decodeURLOrEmptyString(string(req.Body)))
		} else {
			for _, values := range params {
				for _, p := range values {
					res = append(res, decodeURLOrEmptyString(p))
				}
			}
		}
	} else {
		res = append(res, string(req.Body))
	}

	// Parse all query parameters to find base64 strings.
	qIdx := strings.Index(req.Uri, "?")
	if qIdx == -1 {
		return res
	}
	query := req.Uri[qIdx+1:]
	params, err := url.ParseQuery(query)
	if err != nil {
		slog.Warn("could not parse query", slog.String("error", err.Error()), slog.String("query", query))
		return res
	}

	for _, values := range params {
		for _, p := range values {
			res = append(res, decodeURLOrEmptyString(p))
		}
	}
	return res
}

func ExtractUrls(data string) []string {
	// Add regexes for URLs that have no scheme. Specifically also for commands
	// like curl 1.1.1.1/sh
	return urlStrictReg.FindAllString(data, -1)
}

type Extractor interface {
	MetaType() string
	ParseRequest(req *database.Request)
	ParseString(s string)
}

type URLExtractor struct {
	result   map[string]struct{}
	metaType string
}

func NewURLExtractor(result map[string]struct{}) *URLExtractor {
	return &URLExtractor{
		result:   result,
		metaType: "PAYLOAD_LINK",
	}
}

func (u *URLExtractor) MetaType() string {
	return u.metaType
}

func (u *URLExtractor) ParseRequest(req *database.Request) {
	var member struct{}
	for _, s := range StringsFromRequest(req) {
		for _, url := range ExtractUrls(s) {
			u.result[url] = member
		}
	}
}

func (u *URLExtractor) ParseString(s string) {
	var member struct{}
	for _, url := range ExtractUrls(s) {
		u.result[url] = member
	}
}

type Base64Extractor struct {
	result    map[string][]byte
	asciiOnly bool
	metaType  string
}

func NewBase64Extractor(result map[string][]byte, asciiOnly bool) *Base64Extractor {
	return &Base64Extractor{
		result:    result,
		asciiOnly: asciiOnly,
		metaType:  "DECODED_STRING_BASE64",
	}
}

func (b *Base64Extractor) MetaType() string {
	return b.metaType
}

func (b *Base64Extractor) ParseRequest(req *database.Request) {
	for _, v := range StringsFromRequest(req) {
		b.FindAndAdd(v)
	}
}

func (b *Base64Extractor) ParseString(s string) {
	b.FindAndAdd(s)
}

func (b *Base64Extractor) FindAndAdd(data string) int64 {
	allMatches := base64Reg.FindAllString(data, -1)
	if allMatches == nil {
		return 0
	}

	for _, v := range allMatches {
		// Check if there is padding. If so, remove anything that might be there
		// after the padding.
		pIdx := strings.Index(v, "==")
		if pIdx == -1 {
			pIdx = strings.Index(v, "=")
			if pIdx != -1 {
				v = v[0 : pIdx+1]
			}
		} else {
			v = v[0 : pIdx+2]
		}
		// Base64 string are always a multiple length of 4
		sLen := len(v)
		if sLen == 0 || sLen < 4 {
			continue
		}

		quo := sLen % 4
		if quo != 0 {
			if (sLen-quo) >= 4 && v[sLen-1:] == "=" {
				// Give it a final shot when the string ends with padding. We strip the
				// first characters until the string can decode.
				v = v[quo:]
			} else {
				continue
			}
		}

		decoded, err := base64.StdEncoding.DecodeString(v)
		if err == nil {
			// Finally check if the string is ascii or not.
			if !b.asciiOnly || isASCII(string(decoded)) {
				b.result[v] = decoded
			}
		}
	}
	return int64(len(b.result))
}
