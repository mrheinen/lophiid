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
package models

import "time"

type Whois struct {
	ID   int64  `ksql:"id,skipInserts" json:"id"`
	IP   string `ksql:"ip" json:"ip"`
	Data string `ksql:"data" json:"data"`
	Rdap []byte `ksql:"rdap" json:"rdap"`

	Country   string    `ksql:"country" json:"country"`
	CreatedAt time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at"`

	// GeoIP fields from MaxMind City DB.
	GeoIPCountry        string  `ksql:"geoip_country" json:"geoip_country"`
	GeoIPCountryCode    string  `ksql:"geoip_country_code" json:"geoip_country_code"`
	GeoIPContinent      string  `ksql:"geoip_continent" json:"geoip_continent"`
	GeoIPCity           string  `ksql:"geoip_city" json:"geoip_city"`
	GeoIPLatitude       float64 `ksql:"geoip_latitude" json:"geoip_latitude"`
	GeoIPLongitude      float64 `ksql:"geoip_longitude" json:"geoip_longitude"`
	GeoIPTimezone       string  `ksql:"geoip_timezone" json:"geoip_timezone"`
	GeoIPAccuracyRadius uint16  `ksql:"geoip_accuracy_radius" json:"geoip_accuracy_radius"`
	GeoIPIsInEU         bool    `ksql:"geoip_is_in_eu" json:"geoip_is_in_eu"`

	// GeoIP fields from MaxMind ASN DB.
	GeoIPASN    uint   `ksql:"geoip_asn" json:"geoip_asn"`
	GeoIPASNOrg string `ksql:"geoip_asn_org" json:"geoip_asn_org"`

	// The next fields are spefically for the API server.
	RdapString string `json:"rdap_string"` // rdap field converted to string
}

func (c *Whois) ModelID() int64 { return c.ID }
