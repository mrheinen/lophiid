package backend

import (
	"net"
	"testing"
)

//		ipBasedUrl, ip, hostHeader, err := ConvertURLToIPBased(v)

// Test ConvertURLToIPBased
func TestConvertURLToIPBased(t *testing.T) {

	for _, test := range []struct {
		description        string
		url                string
		expectedUrl        string
		expectedIP         string
		expectedHostHeader string
		expectedErr        error
	}{
		{
			description:        "simple url, no explicit port",
			url:                "http://example.org",
			expectedUrl:        "http://1.1.1.1:80",
			expectedIP:         "1.1.1.1",
			expectedHostHeader: "example.org",
			expectedErr:        nil,
		},
		{
			description:        "simple url, no explicit port, ssl",
			url:                "https://example.org",
			expectedUrl:        "https://1.1.1.1:443",
			expectedIP:         "1.1.1.1",
			expectedHostHeader: "example.org",
			expectedErr:        nil,
		},
		{
			description:        "simple url, explicit port",
			url:                "https://example.org:8888/aaa",
			expectedUrl:        "https://1.1.1.1:8888/aaa",
			expectedIP:         "1.1.1.1",
			expectedHostHeader: "example.org:8888",
			expectedErr:        nil,
		},
		{
			description:        "simple url, explicit port, ipv6",
			url:                "https://example.org:8888/aaa",
			expectedUrl:        "https://[2a00:1450:400a:800::2004]:8888/aaa",
			expectedIP:         "2a00:1450:400a:800::2004",
			expectedHostHeader: "example.org:8888",
			expectedErr:        nil,
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			ipUrl, ip, hostHeader, err := ConvertURLToIPBasedImpl(test.url, func(ip string) ([]net.IP, error) {
				return []net.IP{net.ParseIP(test.expectedIP)}, nil
			})

			if ipUrl != test.expectedUrl {
				t.Errorf("expected %s, got %s", test.expectedUrl, ipUrl)
			}

			if ip != test.expectedIP {
				t.Errorf("expected %s, got %s", test.expectedIP, ip)
			}
			if hostHeader != test.expectedHostHeader {
				t.Errorf("expected %s, got %s", test.expectedHostHeader, hostHeader)
			}

			if err != test.expectedErr {
				t.Errorf("expected %s, got %s", test.expectedErr, err)
			}
		})
	}

}
