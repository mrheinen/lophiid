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
package whois

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRdapData = `IP Network:
  Handle: NET-15-235-85-0-1
  Start Address: 15.235.85.0
  End Address: 15.235.85.255
  IP Version: v4
  Name: SD-BHS-BHS8-B811A-MAGGIE-INFRA-002
  Type: ASSIGNMENT
  ParentHandle: NET-15-235-0-0-1
  Status: active
  Port43: whois.arin.net
  Notice:
    Title: Terms of Service
    Description: By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use
  Entity:
    Handle: HO-2
    Role: registrant
    vCard fn: OVH Hosting, Inc.
  Event:
    Action: last changed
    Date: 2022-07-04T15:30:42-04:00
  cidr0_cidrs:
    v4prefix: 15.235.85.0
    length: 24`

func TestRdapParser_GetNetwork_Slash24(t *testing.T) {
	parser := NewRdapParser(testRdapData)
	prefix, err := parser.GetNetwork()
	require.NoError(t, err)

	expected := netip.MustParsePrefix("15.235.85.0/24")
	assert.Equal(t, expected, prefix)
}

func TestRdapParser_GetNetwork_Slash16(t *testing.T) {
	data := `IP Network:
  Start Address: 10.0.0.0
  End Address: 10.0.255.255`

	parser := NewRdapParser(data)
	prefix, err := parser.GetNetwork()
	require.NoError(t, err)

	expected := netip.MustParsePrefix("10.0.0.0/16")
	assert.Equal(t, expected, prefix)
}

func TestRdapParser_GetNetwork_Slash32(t *testing.T) {
	data := `IP Network:
  Start Address: 192.168.1.1
  End Address: 192.168.1.1`

	parser := NewRdapParser(data)
	prefix, err := parser.GetNetwork()
	require.NoError(t, err)

	expected := netip.MustParsePrefix("192.168.1.1/32")
	assert.Equal(t, expected, prefix)
}

func TestRdapParser_GetNetwork_Slash8(t *testing.T) {
	data := `IP Network:
  Start Address: 10.0.0.0
  End Address: 10.255.255.255`

	parser := NewRdapParser(data)
	prefix, err := parser.GetNetwork()
	require.NoError(t, err)

	expected := netip.MustParsePrefix("10.0.0.0/8")
	assert.Equal(t, expected, prefix)
}

func TestRdapParser_GetNetwork_MissingStartAddress(t *testing.T) {
	data := `IP Network:
  End Address: 10.0.0.255`

	parser := NewRdapParser(data)
	_, err := parser.GetNetwork()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Start Address")
}

func TestRdapParser_GetNetwork_MissingEndAddress(t *testing.T) {
	data := `IP Network:
  Start Address: 10.0.0.0`

	parser := NewRdapParser(data)
	_, err := parser.GetNetwork()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "End Address")
}

func TestRdapParser_GetNetwork_InvalidRange(t *testing.T) {
	data := `IP Network:
  Start Address: 10.0.0.0
  End Address: 10.0.0.200`

	parser := NewRdapParser(data)
	_, err := parser.GetNetwork()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "valid CIDR block")
}

func TestRdapParser_GetName(t *testing.T) {
	parser := NewRdapParser(testRdapData)
	assert.Equal(t, "SD-BHS-BHS8-B811A-MAGGIE-INFRA-002", parser.GetName())
}

func TestRdapParser_GetName_Missing(t *testing.T) {
	parser := NewRdapParser("IP Network:\n  Start Address: 10.0.0.0")
	assert.Equal(t, "", parser.GetName())
}

func TestPrefixFromRange_IPv6(t *testing.T) {
	start := netip.MustParseAddr("2001:db8::")
	end := netip.MustParseAddr("2001:db8::ffff")
	prefix, err := prefixFromRange(start, end)
	require.NoError(t, err)

	expected := netip.MustParsePrefix("2001:db8::/112")
	assert.Equal(t, expected, prefix)
}

func TestPrefixFromRange_MismatchedFamilies(t *testing.T) {
	start := netip.MustParseAddr("10.0.0.0")
	end := netip.MustParseAddr("2001:db8::ff")
	_, err := prefixFromRange(start, end)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "address family mismatch")
}
