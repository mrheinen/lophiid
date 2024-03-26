package backend

import (
	"fmt"
	"net"
	"net/url"
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

func ConvertURLToIPBased(targetUrl string) (string, string, string, error) {
	var rIP net.IP
	rHostPort := 0

	u, err := url.Parse(targetUrl)
	if err != nil {
		return "", "", "", err
	}

	rHostHeader := u.Host
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
		netIps, err := net.LookupIP(dnsIP)
		if err != nil {
			return "", "", "", fmt.Errorf("error doing DNS lookup: %w", err)
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

	ipString := rIP.String()
	if rIP.To4() == nil {
		// In this case it's IPv6
		ipString = fmt.Sprintf("[%s]", rIP.String())
	}

	// Now update the parsed URL
	u.Host = fmt.Sprintf("%s:%d", ipString, rHostPort)
	return u.String(), rIP.String(), rHostHeader, err
}
