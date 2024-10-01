package javascript

import (
	"encoding/base64"
	"log/slog"
	"lophiid/pkg/util/decoding"
)

// Contains helper methods to decode strings.
type Encoding struct {
	Base64 Base64 `json:"base64"`
	Uri    Uri    `json:"uri"`
	Html   Html   `json:"html"`
}

type Base64 struct {
}

// util.encoding.base64.decode()
func (d Base64) Decode(s string) string {
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		slog.Warn("unable to decode string", slog.String("input", s), slog.String("error", err.Error()))
		return ""
	}
	return string(dec)
}

// util.encoding.base64.encode()
func (d Base64) Encode(s string) string {
	return base64.RawStdEncoding.EncodeToString([]byte(s))
}

type Uri struct {
}

// util.encoding.uri.decode()
func (u Uri) Decode(s string) string {
	return decoding.DecodeURLOrEmptyString(s, false)
}

type Html struct {
}

// util.encoding.html.decode()
func (u Html) Decode(s string) string {
	return decoding.DecodeHTML(s)
}
