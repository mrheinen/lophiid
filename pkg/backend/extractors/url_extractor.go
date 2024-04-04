package extractors

import (
	"loophid/pkg/database"
	"regexp"
	"strings"

	"mvdan.cc/xurls"
)

var (
	// Yes. These are not the best.. now I do prefer the regexes to be somewhat
	// readable and additionally I also prefer them to rather match to broadly
	// then to miss out potential matches. However I recognize that these can be
	// improved and I'd be happy if you send me better ones ;p
	urlStrictReg = xurls.Strict()
	urlIPReg     = regexp.MustCompile(`[\s\t]+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:[\d]+)?/[a-zA-Z0-9_\-\./\?&:=]*`)
)

func ExtractUrls(data string) []string {
	// Add regexes for URLs that have no scheme. Specifically also for commands
	// like curl 1.1.1.1/sh

	ip := urlIPReg.FindAllString(data, -1)
	sc := urlStrictReg.FindAllString(data, -1)

	retmap := make(map[string]bool)
	var ret []string
	for _, entry := range append(ip, sc...) {
		if strings.Contains(entry, ";") {
			parts := strings.Split(entry, ";")
			entry = parts[0]
		}
		if strings.Contains(entry, "+") {
			parts := strings.Split(entry, "+")
			entry = parts[0]
		}
		centry := strings.TrimSpace(entry)
		if _, ok := retmap[centry]; !ok {
			retmap[centry] = true
			ret = append(ret, centry)
		}
	}
	return ret
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
			// Skip the URL if it contains our honeypot IP.
			if !strings.Contains(url, req.HoneypotIP) {
				u.result[url] = member
			}
		}
	}
}

func (u *URLExtractor) ParseString(s string) {
	var member struct{}
	for _, url := range ExtractUrls(s) {
		u.result[url] = member
	}
}

func (u *URLExtractor) GetMetadatas(requestID int64) []database.RequestMetadata {
	mds := []database.RequestMetadata{}
	for result := range u.result {
		mds = append(mds, database.RequestMetadata{
			Type:      u.MetaType(),
			Data:      result,
			RequestID: requestID,
		})
	}

	return mds
}
