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
package backend

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func IsIPPrivate(ip net.IP) bool {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func netLookupWrapper(target string) ([]net.IP, error) {
	return net.LookupIP(target)
}

func ConvertURLToIPBased(targetUrl string) (string, string, string, error) {
	return ConvertURLToIPBasedImpl(targetUrl, netLookupWrapper)
}

// ConvertURLToIPBasedImpl takes a URL and returns the parameters needed to make
// a safe request.
// We do not want to just reach out to any URL/IP address. Currently we resolve
// the domain of the URL (if needed) and check if it points to a private IP
// address. If it does, then an error is returned.  We then return an updated
// version of the URL with the resolved and checked IP address so we can use it
// directly in the request instead of the domain (we want to avoid a TOCTOU
// issue).  Additionally the original domain is returned in host header format
// so this can be used in the htt request.
func ConvertURLToIPBasedImpl(targetUrl string, lookupFp func(string) ([]net.IP, error)) (ipbasedUrl string, ip string, hostHeader string, myerr error) {
	var rIP net.IP
	rHostPort := 0

	// Regex match targetUrl to see if it starts with a URL scheme.
	matched, err := regexp.MatchString("^[a-z]+://", targetUrl)
	if err != nil {
		return "", "", "", fmt.Errorf("unable to match regex on URL: %s  %s", targetUrl, err)
	}

	if matched {
		if !strings.HasPrefix(targetUrl, "http") {
			return "", "", "", fmt.Errorf("unable to support scheme for URL: %s ", targetUrl)
		}
	} else {
		targetUrl = fmt.Sprintf("http://%s", targetUrl)
	}

	u, err := url.Parse(targetUrl)
	if err != nil {
		return "", "", "", err
	}

	hostHeader = u.Host
	dnsIP := u.Host
	// Parse the host field which is in the format <ip/domain>:[<port>]?
	if strings.Contains(u.Host, ":") {
		host, port, err := net.SplitHostPort(u.Host)
		if err != nil {
			return "", "", "", fmt.Errorf("error splitting host field: %w", err)
		}

		dnsIP = host
		rHostPort, err = strconv.Atoi(port)
		if err != nil {
			return "", "", "", fmt.Errorf("cannot handle host port: %d", rHostPort)
		}
	}

	// Here we do not know if dnsIP is an IP or domain. We try to parse it as an
	// IP and if that doesn't work, we'll try to resolve it.
	rIP = net.ParseIP(dnsIP)
	if rIP == nil {
		netIps, err := lookupFp(dnsIP)
		if err != nil {
			return "", "", "", fmt.Errorf("error doing DNS lookup of %s: %w", dnsIP, err)
		}
		rIP = netIps[0]
	}

	if IsIPPrivate(rIP) {
		return "", "", "", fmt.Errorf("IP %s is private", rIP.String())
	}

	if rHostPort == 0 {
		if u.Scheme == "https" {
			rHostPort = 443
		} else {
			rHostPort = 80
		}
	}

	// Now update the parsed URL
	u.Host = net.JoinHostPort(rIP.String(), fmt.Sprintf("%d", rHostPort))
	return u.String(), rIP.String(), hostHeader, err
}

func HasParseableContent(fileUrl string, mime string) bool {
	consumableContentTypes := map[string]bool{
		"application/x-shellscript": true,
		"application/x-sh":          true,
		"application/x-perl":        true,
		"text/x-shellscript":        true,
		"text/x-sh":                 true,
		"text/x-perl":               true,
		"text/plain":                true,
	}

	parsedUrl, err := url.Parse(fileUrl)
	if err != nil {
		slog.Warn("could not parse URL", slog.String("url", fileUrl))
		return false
	}

	contentParts := strings.Split(mime, ";")
	_, hasGoodContent := consumableContentTypes[contentParts[0]]
	return hasGoodContent || strings.HasSuffix(parsedUrl.Path, ".sh") ||
		strings.HasSuffix(parsedUrl.Path, ".pl") ||
		strings.HasSuffix(parsedUrl.Path, ".bat") ||
		strings.HasSuffix(parsedUrl.Path, ".rb") ||
		strings.HasSuffix(parsedUrl.Path, ".py")
}
