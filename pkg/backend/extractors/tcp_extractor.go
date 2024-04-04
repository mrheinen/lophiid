package extractors

import (
	"fmt"
	"log/slog"
	"loophid/pkg/database"
	"regexp"
	"strconv"
)

var (
	devTCPIPv4Reg = regexp.MustCompile(`/dev/tcp/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/([\d]+)`)
	devTCPIPv6Reg = regexp.MustCompile(`/dev/tcp/([0-9a-fA-F:]+)/([\d]+)`)
	devTCPHostReg = regexp.MustCompile(`/dev/tcp/([0-9a-zA-Z\-\.]+\.[a-zA-Z]{2,})/([\d]+)`)
)

// TCPExtractor extracts IP/hostnames and port combinations from
// /dev/tcp/ip/port addresses.
type TCPExtractor struct {
	result   map[string]int
	metaType string
}

func NewTCPExtractor(result map[string]int) *TCPExtractor {
	return &TCPExtractor{
		result:   result,
		metaType: "PAYLOAD_TCP_LINK",
	}
}

func (u *TCPExtractor) MetaType() string {
	return u.metaType
}

func (u *TCPExtractor) ParseRequest(req *database.Request) {
	for _, s := range StringsFromRequest(req) {
		u.ParseString(s)
	}
}

func (u *TCPExtractor) ParseString(s string) {
	ipv4Matches := devTCPIPv4Reg.FindAllStringSubmatch(s, -1)
	ipv6sMatches := devTCPIPv6Reg.FindAllStringSubmatch(s, -1)
	hostMatches := devTCPHostReg.FindAllStringSubmatch(s, -1)

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

func (u *TCPExtractor) GetMetadatas(requestID int64) []database.RequestMetadata {
	mds := []database.RequestMetadata{}
	for k, v := range u.result {
		mds = append(mds, database.RequestMetadata{
			Type:      u.MetaType(),
			Data:      fmt.Sprintf("/dev/tcp/%s/%d", k, v),
			RequestID: requestID,
		})
	}

	return mds
}
