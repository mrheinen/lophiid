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

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSessionIDCorrelator_Match(t *testing.T) {
	c := &SessionIDCorrelator{}
	seeds := NewCampaignSeedData()
	seeds.SessionIDs[42] = true

	assert.True(t, c.Match(CandidateRequest{SessionID: 42}, seeds))
	assert.False(t, c.Match(CandidateRequest{SessionID: 99}, seeds))
	assert.False(t, c.Match(CandidateRequest{SessionID: 0}, seeds))
}

func TestSourceIPCorrelator_Match(t *testing.T) {
	c := &SourceIPCorrelator{}
	seeds := NewCampaignSeedData()
	seeds.SourceIPs["1.2.3.4"] = true

	assert.True(t, c.Match(CandidateRequest{SourceIP: "1.2.3.4"}, seeds))
	assert.False(t, c.Match(CandidateRequest{SourceIP: "5.6.7.8"}, seeds))
	assert.False(t, c.Match(CandidateRequest{SourceIP: ""}, seeds))
}

func TestSubnetCorrelator_Match(t *testing.T) {
	c := &SubnetCorrelator{}
	seeds := NewCampaignSeedData()
	seeds.Subnets["203.0.113.0/24"] = true

	assert.True(t, c.Match(CandidateRequest{Subnet: "203.0.113.0/24"}, seeds))
	assert.False(t, c.Match(CandidateRequest{Subnet: "198.51.100.0/24"}, seeds))
	assert.False(t, c.Match(CandidateRequest{Subnet: ""}, seeds))
}

func TestSubnetCorrelator_MatchContainment(t *testing.T) {
	c := &SubnetCorrelator{}
	seeds := NewCampaignSeedData()
	seeds.Subnets["203.0.113.0/24"] = true

	// A smaller subnet within the seed's /24 should match.
	assert.True(t, c.Match(CandidateRequest{Subnet: "203.0.113.0/28"}, seeds))
	assert.True(t, c.Match(CandidateRequest{Subnet: "203.0.113.128/25"}, seeds))

	// A subnet outside the seed range should not match.
	assert.False(t, c.Match(CandidateRequest{Subnet: "203.0.114.0/28"}, seeds))

	// A larger subnet that contains the seed should also match.
	assert.True(t, c.Match(CandidateRequest{Subnet: "203.0.112.0/20"}, seeds))
}

func TestBuildCorrelators(t *testing.T) {
	correlators := BuildCorrelators([]string{"session_id", "source_ip", "subnet"})
	assert.Equal(t, 3, len(correlators))
	assert.Equal(t, "session_id", correlators[0].Name())
	assert.Equal(t, "source_ip", correlators[1].Name())
	assert.Equal(t, "subnet", correlators[2].Name())
}

func TestBuildCorrelators_Empty(t *testing.T) {
	correlators := BuildCorrelators(nil)
	assert.Nil(t, correlators)
}

func TestBuildCorrelators_Unknown(t *testing.T) {
	correlators := BuildCorrelators([]string{"unknown_feature"})
	assert.Equal(t, 0, len(correlators))
}

func TestMatchAny_SessionMatch(t *testing.T) {
	correlators := BuildCorrelators([]string{"session_id", "source_ip"})
	seeds := NewCampaignSeedData()
	seeds.SessionIDs[42] = true

	assert.True(t, MatchAny(correlators, CandidateRequest{SessionID: 42, SourceIP: "9.9.9.9"}, seeds))
}

func TestMatchAny_IPMatch(t *testing.T) {
	correlators := BuildCorrelators([]string{"session_id", "source_ip"})
	seeds := NewCampaignSeedData()
	seeds.SourceIPs["1.2.3.4"] = true

	assert.True(t, MatchAny(correlators, CandidateRequest{SessionID: 99, SourceIP: "1.2.3.4"}, seeds))
}

func TestMatchAny_NoMatch(t *testing.T) {
	correlators := BuildCorrelators([]string{"session_id", "source_ip"})
	seeds := NewCampaignSeedData()
	seeds.SessionIDs[42] = true
	seeds.SourceIPs["1.2.3.4"] = true

	assert.False(t, MatchAny(correlators, CandidateRequest{SessionID: 99, SourceIP: "5.6.7.8"}, seeds))
}

func TestMatchAny_EmptyCorrelators(t *testing.T) {
	seeds := NewCampaignSeedData()
	seeds.SourceIPs["1.2.3.4"] = true

	assert.False(t, MatchAny(nil, CandidateRequest{SourceIP: "1.2.3.4"}, seeds))
}
