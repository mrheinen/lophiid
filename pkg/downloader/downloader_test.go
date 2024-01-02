package downloader

import (
	"net"
	"testing"
	"time"
)

func TestIsPrivate(t *testing.T) {
	for _, test := range []struct {
		description string
		ip          string
		isPrivate   bool
	}{
		{
			description: "is private",
			ip:          "127.0.0.1",
			isPrivate:   true,
		},
		{
			description: "is private",
			ip:          "192.168.1.1",
			isPrivate:   true,
		},
		{
			description: "is not private",
			ip:          "8.8.8.8",
			isPrivate:   false,
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			d := NewHTTPDownloader("/foo", time.Minute)

			isRes := d.isPrivateIP(net.ParseIP(test.ip))
			if isRes != test.isPrivate {
				t.Errorf("expected isPrivate %t but got %t", test.isPrivate, isRes)
			}

		})
	}
}

func TestGetIPParts(t *testing.T) {
	for _, test := range []struct {
		description string
		url         string
		ip          net.IP
		host        string
		port        int
	}{
		{
			description: "resolve localhost ok",
			url:         "http://localhost:8000/aaaa",
			ip:          net.ParseIP("::1"),
			port:        8000,
			host:        "localhost",
		},
		{
			description: "resolve localhost without port",
			url:         "http://localhost/aaaa",
			ip:          net.ParseIP("::1"),
			port:        0,
			host:        "localhost",
		},
		{
			description: "handle ip with port",
			url:         "http://8.8.8.8:8888/aaaa",
			ip:          net.ParseIP("8.8.8.8"),
			port:        8888,
			host:        "8.8.8.8",
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			d := NewHTTPDownloader("/foo", time.Minute)

			h, ip, port, _ := d.getIPForUrl(test.url)
			if h != test.host {
				t.Errorf("expected %s, got %s", test.host, h)
			}

			if ip.String() != test.ip.String() {
				t.Errorf("expected %s, got %s", test.ip, ip)
			}

			if port != test.port {
				t.Errorf("expected %d, got %d", test.port, port)
			}

		})
	}
}
