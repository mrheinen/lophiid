package extractors

import (
	"fmt"
	"lophiid/pkg/database/models"
)

// ExtractorCollection initiates a bunch of extractors, configured them and
// makes them available as a collection to the backend. Let's say it's a far
// from elegant solution but it does the job.
type ExtractorCollection struct {
	linksMap        map[string]struct{}
	tcpAddressesMap map[string]int
	pingMap         map[string]int
	ncMap           map[string]int
	b64Map          map[string][]byte
	uniMap          map[string]string
	extractors      []Extractor
}

func NewExtractorCollection(asciiOnly bool) *ExtractorCollection {
	ae := ExtractorCollection{
		linksMap:        make(map[string]struct{}),
		tcpAddressesMap: make(map[string]int),
		pingMap:         make(map[string]int),
		ncMap:           make(map[string]int),
		b64Map:          make(map[string][]byte),
		uniMap:          make(map[string]string),
	}

	linkExtractor := NewURLExtractor(ae.linksMap)
	tcpExtractor := NewTCPExtractor(ae.tcpAddressesMap)
	pingExtractor := NewPingExtractor(ae.pingMap)
	ncExtractor := NewNCExtractor(ae.ncMap)

	base64Extractor := NewBase64Extractor(ae.b64Map, asciiOnly)
	base64Extractor.AddSubExtractor(linkExtractor)
	base64Extractor.AddSubExtractor(tcpExtractor)
	base64Extractor.AddSubExtractor(pingExtractor)
	base64Extractor.AddSubExtractor(ncExtractor)

	uniExtractor := NewUnicodeExtractor(ae.uniMap, asciiOnly)
	uniExtractor.AddSubExtractor(base64Extractor)

	ae.extractors = []Extractor{base64Extractor, linkExtractor, tcpExtractor, uniExtractor, pingExtractor, ncExtractor}
	return &ae
}

func (a *ExtractorCollection) ParseRequest(req *models.Request) {
	for _, ex := range a.extractors {
		ex.ParseRequest(req)
	}
}

// IterateMetadata iterares over the metadata and calls the callback on each
// item. If the callback returns an error than the loop is broken.
func (a *ExtractorCollection) IterateMetadata(reqId int64, cb func(m *models.RequestMetadata) error) error {
	for _, ex := range a.extractors {
		for _, m := range ex.GetMetadatas(reqId) {
			if err := cb(&m); err != nil {
				return fmt.Errorf("error in callback: %s", err)
			}
		}
	}

	return nil
}

// Get all metadata from all extractors.
func (a *ExtractorCollection) AllMetadata(reqId int64) []models.RequestMetadata {
	ret := []models.RequestMetadata{}
	for _, ex := range a.extractors {
		ret = append(ret, ex.GetMetadatas(reqId)...)
	}

	return ret
}
