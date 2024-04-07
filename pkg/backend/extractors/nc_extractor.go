package extractors

import (
	"fmt"
	"log/slog"
	"loophid/pkg/database"
	"regexp"
	"strconv"
)

var (
	ncIPv4Reg = regexp.MustCompile(`nc\s+(?:\-4\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([\d]+)`)
	ncIPv6Reg = regexp.MustCompile(`nc\s+(?:\-6\s+)?([0-9a-fA-F:]+)\s+([\d]+)`)
	ncHostReg = regexp.MustCompile(`nc\s+(?:\-[46]{1}\s)?([0-9a-zA-Z\-\.]+\.[a-zA-Z]{2,})\s+([\d]+)`)
)

type NCExtractor struct {
	result   map[string]int
	metaType string
}

func NewNCExtractor(result map[string]int) *NCExtractor {
	return &NCExtractor{
		result:   result,
		metaType: "PAYLOAD_NETCAT",
	}
}

func (u *NCExtractor) MetaType() string {
	return u.metaType
}

func (u *NCExtractor) ParseRequest(req *database.Request) {
	for _, s := range StringsFromRequest(req) {
		u.ParseString(s)
	}
}

func (u *NCExtractor) ParseString(s string) {
	ipv4Matches := ncIPv4Reg.FindAllStringSubmatch(s, -1)
	ipv6sMatches := ncIPv6Reg.FindAllStringSubmatch(s, -1)
	hostMatches := ncHostReg.FindAllStringSubmatch(s, -1)

	for _, matches := range append(append(ipv6sMatches, hostMatches...), ipv4Matches...) {
		address := matches[1]
		port := matches[2]

		intPort, err := strconv.Atoi(port)
		if err != nil {
			slog.Warn("unable to parse port", slog.String("port", port), slog.String("error", err.Error()))
		}

		u.result[address] = intPort
	}
}

func (u *NCExtractor) GetMetadatas(requestID int64) []database.RequestMetadata {
	mds := []database.RequestMetadata{}
	for k, v := range u.result {
		mds = append(mds, database.RequestMetadata{
			Type:      u.MetaType(),
			Data:      fmt.Sprintf("%s %d", k, v),
			RequestID: requestID,
		})
	}

	return mds
}
