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
package campaign

import "net/netip"

// Correlator matches non-malicious requests to a campaign based on shared
// identifiers with the campaign's malicious seeds.
type Correlator interface {
	// Name returns the correlator identifier (matches correlation_features config).
	Name() string
	// Match returns true if the candidate request should be included in the
	// campaign based on this correlator's criteria.
	Match(candidate CandidateRequest, seeds CampaignSeedData) bool
}

// CandidateRequest holds the minimal fields needed for correlation matching.
type CandidateRequest struct {
	RequestID int64
	SourceIP  string
	SessionID int64
	Subnet    string // Network range from whois, if available.
}

// CampaignSeedData holds the aggregated identifiers from a campaign's
// malicious seeds, used for correlation matching.
type CampaignSeedData struct {
	SessionIDs map[int64]bool
	SourceIPs  map[string]bool
	Subnets    map[string]bool
}

// NewCampaignSeedData creates an empty CampaignSeedData.
func NewCampaignSeedData() CampaignSeedData {
	return CampaignSeedData{
		SessionIDs: make(map[int64]bool),
		SourceIPs:  make(map[string]bool),
		Subnets:    make(map[string]bool),
	}
}

// SessionIDCorrelator matches by shared session ID.
type SessionIDCorrelator struct{}

func (c *SessionIDCorrelator) Name() string { return "session_id" }

// Match returns true if the candidate's session ID is in the campaign's seed session IDs.
func (c *SessionIDCorrelator) Match(candidate CandidateRequest, seeds CampaignSeedData) bool {
	return candidate.SessionID != 0 && seeds.SessionIDs[candidate.SessionID]
}

// SourceIPCorrelator matches by shared source IP.
type SourceIPCorrelator struct{}

func (c *SourceIPCorrelator) Name() string { return "source_ip" }

// Match returns true if the candidate's source IP is in the campaign's seed source IPs.
func (c *SourceIPCorrelator) Match(candidate CandidateRequest, seeds CampaignSeedData) bool {
	return candidate.SourceIP != "" && seeds.SourceIPs[candidate.SourceIP]
}

// SubnetCorrelator matches by shared network range (from whois).
type SubnetCorrelator struct{}

func (c *SubnetCorrelator) Name() string { return "subnet" }

// Match returns true if the candidate's subnet overlaps with any of the
// campaign's seed subnets. This handles both exact matches and containment
// (e.g. a /28 candidate matching a /24 seed).
func (c *SubnetCorrelator) Match(candidate CandidateRequest, seeds CampaignSeedData) bool {
	if candidate.Subnet == "" {
		return false
	}
	// Fast path: exact match.
	if seeds.Subnets[candidate.Subnet] {
		return true
	}
	candPrefix, err := netip.ParsePrefix(candidate.Subnet)
	if err != nil {
		return false
	}
	for s := range seeds.Subnets {
		seedPrefix, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		if seedPrefix.Contains(candPrefix.Addr()) || candPrefix.Contains(seedPrefix.Addr()) {
			return true
		}
	}
	return false
}

// BuildCorrelators creates the configured set of correlators from feature names.
func BuildCorrelators(features []string) []Correlator {
	var correlators []Correlator
	for _, f := range features {
		switch f {
		case "session_id":
			correlators = append(correlators, &SessionIDCorrelator{})
		case "source_ip":
			correlators = append(correlators, &SourceIPCorrelator{})
		case "subnet":
			correlators = append(correlators, &SubnetCorrelator{})
		}
	}
	return correlators
}

// MatchAny returns true if any correlator matches the candidate.
func MatchAny(correlators []Correlator, candidate CandidateRequest, seeds CampaignSeedData) bool {
	for _, c := range correlators {
		if c.Match(candidate, seeds) {
			return true
		}
	}
	return false
}
