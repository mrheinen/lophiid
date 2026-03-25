// Lophiid distributed honeypot
// Copyright (C) 2023-2026 Niels Heinen
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
package whois

import (
	"fmt"
	"net/netip"
	"path/filepath"

	geoip2 "github.com/oschwald/geoip2-golang/v2"
)

// GeoIPResult holds the result of a GeoIP lookup combining data from the
// MaxMind City and ASN databases.
type GeoIPResult struct {
	Country        string
	CountryCode    string
	Continent      string
	City           string
	Latitude       float64
	Longitude      float64
	Timezone       string
	AccuracyRadius uint16
	IsInEU         bool
	ASN            uint
	ASNOrg         string
}

// GeoIPLookup is the interface for performing GeoIP lookups. Implementations
// must be safe for concurrent use.
type GeoIPLookup interface {
	Lookup(ip string) (*GeoIPResult, error)
	Close() error
}

// MaxMindGeoIPLookup performs GeoIP lookups using MaxMind GeoLite2 databases.
type MaxMindGeoIPLookup struct {
	cityReader *geoip2.Reader
	asnReader  *geoip2.Reader
}

// NewMaxMindGeoIPLookup creates a new MaxMindGeoIPLookup by opening the
// GeoLite2-City.mmdb and GeoLite2-ASN.mmdb files from the given directory.
func NewMaxMindGeoIPLookup(dbDir string) (*MaxMindGeoIPLookup, error) {
	cityPath := filepath.Join(dbDir, "GeoLite2-City.mmdb")
	asnPath := filepath.Join(dbDir, "GeoLite2-ASN.mmdb")

	cityReader, err := geoip2.Open(cityPath)
	if err != nil {
		return nil, fmt.Errorf("opening GeoLite2-City database at %s: %w", cityPath, err)
	}

	asnReader, err := geoip2.Open(asnPath)
	if err != nil {
		cityReader.Close()
		return nil, fmt.Errorf("opening GeoLite2-ASN database at %s: %w", asnPath, err)
	}

	return &MaxMindGeoIPLookup{
		cityReader: cityReader,
		asnReader:  asnReader,
	}, nil
}

// Lookup performs a GeoIP lookup for the given IP address string, returning
// combined City and ASN data.
func (m *MaxMindGeoIPLookup) Lookup(ip string) (*GeoIPResult, error) {
	parsedIP, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address %s: %w", ip, err)
	}

	result := &GeoIPResult{}

	cityRecord, err := m.cityReader.City(parsedIP)
	if err != nil {
		return nil, fmt.Errorf("city lookup for %s: %w", ip, err)
	}

	result.Country = cityRecord.Country.Names.English
	result.CountryCode = cityRecord.Country.ISOCode
	result.Continent = cityRecord.Continent.Code
	result.City = cityRecord.City.Names.English
	result.Timezone = cityRecord.Location.TimeZone
	result.AccuracyRadius = cityRecord.Location.AccuracyRadius
	result.IsInEU = cityRecord.Country.IsInEuropeanUnion

	if cityRecord.Location.Latitude != nil {
		result.Latitude = *cityRecord.Location.Latitude
	}
	if cityRecord.Location.Longitude != nil {
		result.Longitude = *cityRecord.Location.Longitude
	}

	asnRecord, err := m.asnReader.ASN(parsedIP)
	if err != nil {
		return nil, fmt.Errorf("ASN lookup for %s: %w", ip, err)
	}

	result.ASN = asnRecord.AutonomousSystemNumber
	result.ASNOrg = asnRecord.AutonomousSystemOrganization

	return result, nil
}

// Close closes both the City and ASN database readers.
func (m *MaxMindGeoIPLookup) Close() error {
	var errs []error
	if err := m.cityReader.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := m.asnReader.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("closing GeoIP databases: %v", errs)
	}
	return nil
}

// FakeGeoIPLookup is a no-op implementation of GeoIPLookup for testing.
type FakeGeoIPLookup struct {
	ResultToReturn *GeoIPResult
	ErrorToReturn  error
}

// Lookup returns the preconfigured result and error.
func (f *FakeGeoIPLookup) Lookup(ip string) (*GeoIPResult, error) {
	return f.ResultToReturn, f.ErrorToReturn
}

// Close is a no-op.
func (f *FakeGeoIPLookup) Close() error {
	return nil
}
