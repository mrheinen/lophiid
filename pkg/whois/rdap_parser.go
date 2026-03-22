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
	"math/bits"
	"net/netip"
	"strings"
)

// RdapParser parses RDAP text output to extract network information.
type RdapParser struct {
	data string
}

// NewRdapParser creates a new RdapParser initialized with the given RDAP text data.
func NewRdapParser(data string) *RdapParser {
	return &RdapParser{data: data}
}

// GetNetwork parses the Start Address and End Address from the RDAP data and
// returns the corresponding network as a netip.Prefix.
func (r *RdapParser) GetNetwork() (netip.Prefix, error) {
	startStr, err := r.extractField("Start Address")
	if err != nil {
		return netip.Prefix{}, err
	}
	endStr, err := r.extractField("End Address")
	if err != nil {
		return netip.Prefix{}, err
	}

	startAddr, err := netip.ParseAddr(startStr)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parsing start address %q: %w", startStr, err)
	}
	endAddr, err := netip.ParseAddr(endStr)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parsing end address %q: %w", endStr, err)
	}

	return prefixFromRange(startAddr, endAddr)
}

// GetName extracts the network Name field from the RDAP data (e.g. "AMAZON-ARN").
func (r *RdapParser) GetName() string {
	name, err := r.extractField("Name")
	if err != nil {
		return ""
	}
	return name
}

// extractField finds a line matching "  <field>: <value>" and returns the trimmed value.
func (r *RdapParser) extractField(field string) (string, error) {
	prefix := field + ":"
	for _, line := range strings.Split(r.data, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, prefix)), nil
		}
	}
	return "", fmt.Errorf("field %q not found in RDAP data", field)
}

// prefixFromRange computes a netip.Prefix from a start and end address pair.
// The range must represent a valid CIDR block (i.e. start is network-aligned
// and end is the broadcast address for that prefix length).
func prefixFromRange(start, end netip.Addr) (netip.Prefix, error) {
	if start.Is4() != end.Is4() {
		return netip.Prefix{}, fmt.Errorf("address family mismatch: start=%s end=%s", start, end)
	}

	startBytes := start.As16()
	endBytes := end.As16()

	// XOR start and end; for a valid CIDR the result must be a contiguous
	// block of zero bits followed by a contiguous block of one bits.
	totalBits := 128
	if start.Is4() {
		totalBits = 32
	}

	// Compute host bits by counting trailing ones in the XOR.
	var xorBytes [16]byte
	for i := range 16 {
		xorBytes[i] = startBytes[i] ^ endBytes[i]
	}

	// Count host bits from the end.
	hostBits := 0
	for i := 15; i >= 0; i-- {
		if xorBytes[i] == 0xFF {
			hostBits += 8
			continue
		}
		if xorBytes[i] != 0 {
			// The remaining byte must be all trailing ones (e.g. 0x1F = 00011111).
			trailing := bits.TrailingZeros8(^xorBytes[i])
			if xorBytes[i] != (1<<trailing)-1 {
				return netip.Prefix{}, fmt.Errorf("range %s-%s does not represent a valid CIDR block", start, end)
			}
			hostBits += trailing
		}
		// All higher bytes in XOR must be zero.
		for j := i - 1; j >= 0; j-- {
			if xorBytes[j] != 0 {
				return netip.Prefix{}, fmt.Errorf("range %s-%s does not represent a valid CIDR block", start, end)
			}
		}
		break
	}

	prefixLen := totalBits - hostBits

	// For IPv4 addresses stored in 16-byte form, adjust for the 12-byte
	// IPv4-in-IPv6 prefix.
	if start.Is4() {
		// netip stores IPv4 as 16 bytes with a ::ffff: prefix; our loop counted
		// from byte 15 which is correct for the last 4 bytes, but we need to
		// ensure the prefix length is relative to 32 bits.
		if prefixLen < 0 || prefixLen > 32 {
			return netip.Prefix{}, fmt.Errorf("computed invalid prefix length %d for IPv4 range", prefixLen)
		}
	}

	return netip.PrefixFrom(start, prefixLen), nil
}
