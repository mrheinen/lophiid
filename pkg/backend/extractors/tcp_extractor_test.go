package extractors

import (
	"fmt"
	"loophid/pkg/database"
	"testing"
)

func TestTCPExtractor(t *testing.T) {
	for _, test := range []struct {
		description string
		request     database.Request
		tcpsToFind  map[string]int
	}{
		{
			description: "finds tcp address with IP",
			request: database.Request{
				Uri:  "/",
				Body: []byte("ssadsads /dev/tcp/1.1.1.1/8080 aa"),
			},
			tcpsToFind: map[string]int{"1.1.1.1": 8080},
		},
		{
			description: "finds tcp address with IP (more embedded)",
			request: database.Request{
				Uri:  "/",
				Body: []byte("ssadsads+/dev/tcp/1.1.1.1/8080;aa"),
			},
			tcpsToFind: map[string]int{"1.1.1.1": 8080},
		},
		{
			description: "finds tcp address with hostname",
			request: database.Request{
				Uri:  "/",
				Body: []byte("ssadsads /dev/tcp/example.org/8080 aa"),
			},
			tcpsToFind: map[string]int{"example.org": 8080},
		},
		{
			description: "finds tcp address with IPv6",
			request: database.Request{
				Uri:  "/",
				Body: []byte("ssadsads /dev/tcp/2a00:1450:400a:800::200e/8080 aa"),
			},
			tcpsToFind: map[string]int{"2a00:1450:400a:800::200e": 8080},
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			result := make(map[string]int)
			te := NewTCPExtractor(result)
			te.ParseRequest(&test.request)

			if len(result) != len(test.tcpsToFind) {
				t.Errorf("expected %d tcp addresses but found %d (%v)", len(test.tcpsToFind), len(result), result)
			}

			mds := te.GetMetadatas(42)
			for k, v := range test.tcpsToFind {
				rv, ok := result[k]
				if !ok {
					t.Errorf("expected to find: %s", k)
					continue
				}

				if rv != v {
					t.Errorf("expected port %d but found %d", v, rv)
				}

				for _, md := range mds {
					if md.Data != fmt.Sprintf("/dev/tcp/%s/%d", k, v) {
						t.Errorf("expected: %s, found: %s", fmt.Sprintf("/dev/tcp/%s/%d", k, v), md.Data)
					}

					if md.Type != "PAYLOAD_TCP_LINK" {
						t.Errorf("expected PAYLOAD_TCP_LINK, found %s", md.Type)
					}
				}
			}
		})
	}
}
