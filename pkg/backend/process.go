package backend

import (
	"encoding/base64"
	"html"
	"net/url"
	"regexp"
	"strings"
)

func decodeURL(encoded string) (string, error) {
	if !strings.Contains(encoded, "%") {
		return encoded, nil
	}

	// This is a special case and in preparation of the Bae64 encodeing we do
	// later on. We may have to rethink whether to keep this here or move it
	// somewhere else.  Anyway, a + in the URL is a space.
	decoded := strings.ReplaceAll(encoded, "+", " ")
	return url.QueryUnescape(decoded)
}

func decodeHTML(encoded string) string {
	if strings.Contains(encoded, "&") {
		return html.UnescapeString(encoded)
	}
	return encoded
}

func FindBase64Strings(data string) map[string][]byte {
	rm := make(map[string][]byte)
	r := regexp.MustCompile(`([a-zA-Z0-9=/+]*)`)

	allMatches := r.FindAllString(data, -1)
	if allMatches == nil {
		return rm
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
			rm[v] = decoded
		}
	}
	return rm
}
