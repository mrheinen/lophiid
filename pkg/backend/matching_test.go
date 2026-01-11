// Lophiid distributed honeypot
// Copyright (C) 2026 Niels Heinen
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
package backend

import (
	"lophiid/pkg/database/models"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetMatchedRuleBasic(t *testing.T) {
	bunchOfRules := []models.ContentRule{
		{ID: 1, AppID: 1, Method: "ANY", Ports: []int{80}, Uri: "/42", UriMatching: "exact", ContentID: 42},
		{ID: 3, AppID: 2, Method: "GET", Ports: []int{80}, Uri: "/prefix", UriMatching: "prefix", ContentID: 43},
		{ID: 4, AppID: 3, Method: "GET", Ports: []int{80}, Uri: "contains", UriMatching: "contains", ContentID: 44},
		{ID: 5, AppID: 4, Method: "GET", Ports: []int{80}, Uri: "suffix", UriMatching: "suffix", ContentID: 45},
		{ID: 6, AppID: 4, Method: "GET", Ports: []int{80}, Uri: "^/a[8-9/]*", UriMatching: "regex", ContentID: 46},
		{ID: 7, AppID: 7, Method: "GET", Ports: []int{443}, Uri: "/eeee", UriMatching: "exact", ContentID: 42},
		{ID: 8, AppID: 8, Method: "GET", Ports: []int{8888}, Uri: "/eeee", UriMatching: "exact", ContentID: 42},
		{ID: 9, AppID: 9, Method: "GET", Ports: []int{80}, Body: "woohoo", BodyMatching: "exact", ContentID: 42},
		{ID: 10, AppID: 9, Method: "GET", Ports: []int{80}, Body: "/etc/passwd", BodyMatching: "contains", ContentID: 42},
		{ID: 11, AppID: 9, Method: "GET", Ports: []int{80}, Uri: "/pppaaattthhh", UriMatching: "exact", Body: "/etc/hosts", BodyMatching: "contains", ContentID: 42},
		{ID: 12, AppID: 4, Method: "POST", Ports: []int{80}, Uri: "suffix", UriMatching: "suffix", ContentID: 77},
		{ID: 13, AppID: 4, Method: "POST", Ports: []int{80}, Uri: "/same", UriMatching: "exact", Body: "body", BodyMatching: "exact", ContentID: 77},
		{ID: 14, AppID: 4, Method: "POST", Ports: []int{80}, Uri: "/same", UriMatching: "exact", ContentID: 77},
	}

	for _, test := range []struct {
		description           string
		requestInput          models.Request
		contentRulesInput     []models.ContentRule
		contentRuleIDExpected int64
		errorExpected         bool
	}{
		{
			description: "matched nothing ",
			requestInput: models.Request{
				Uri:    "/fddfffd",
				Port:   80,
				Method: "GET",
			},
			contentRulesInput: bunchOfRules,
			errorExpected:     true,
		},
		{
			description: "matched one rule (exact) ",
			requestInput: models.Request{
				Uri:    "/42",
				Port:   80,
				Method: "GET",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 1,
			errorExpected:         false,
		},
		{
			description: "matched one rule (prefix) ",
			requestInput: models.Request{
				Uri:    "/prefixdsfsfdf",
				Port:   80,
				Method: "GET",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 3,
			errorExpected:         false,
		},

		{
			description: "matched one rule (contains) ",
			requestInput: models.Request{
				Uri:    "/sddsadcontainsfdfd",
				Port:   80,
				Method: "GET",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 4,
			errorExpected:         false,
		},
		{
			description: "matched one rule (suffix) ",
			requestInput: models.Request{
				Uri:    "/ttttt?aa=suffix",
				Port:   80,
				Method: "GET",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 5,
			errorExpected:         false,
		},
		{
			description: "matched one rule (suffix) ",
			requestInput: models.Request{
				Uri:    "/ttttt?aa=suffix",
				Port:   80,
				Method: "POST",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 12,
			errorExpected:         false,
		},

		{
			description: "matched one rule (regex) ",
			requestInput: models.Request{
				Uri:    "/a898989898",
				Port:   80,
				Method: "GET",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 6,
			errorExpected:         false,
		},
		{
			description: "matched one rule (on port) ",
			requestInput: models.Request{
				Uri:    "/eeee",
				Port:   8888,
				Method: "GET",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 8,
			errorExpected:         false,
		},
		{
			description: "matched one rule (uri and body)  ",
			requestInput: models.Request{
				Uri:    "/same",
				Port:   80,
				Body:   []byte("body"),
				Method: "POST",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 13,
			errorExpected:         false,
		},

		{
			description: "matched on body alone (exact) ",
			requestInput: models.Request{
				Uri:    "/eeee",
				Port:   80,
				Body:   []byte("woohoo"),
				Method: "GET",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 9,
			errorExpected:         false,
		},

		{
			description: "matched on body alone (contains) ",
			requestInput: models.Request{
				Uri:    "/eeee",
				Port:   80,
				Body:   []byte("asdssad /etc/passwd sdds"),
				Method: "GET",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 10,
			errorExpected:         false,
		},
		{
			description: "matched on body and path (contains) ",
			requestInput: models.Request{
				Uri:    "/pppaaattthhh",
				Port:   80,
				Body:   []byte("asdssad /etc/hosts sdds"),
				Method: "GET",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 11,
			errorExpected:         false,
		},
	} {
		t.Run(test.description, func(t *testing.T) {

			matchedRule, err := GetMatchedRule(test.contentRulesInput, &test.requestInput, models.NewSession())
			if test.errorExpected {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, test.contentRuleIDExpected, matchedRule.ID)
		})
	}
}

func TestGetMatchedRuleSameApp(t *testing.T) {
	bunchOfRules := []models.ContentRule{
		{ID: 1, AppID: 1, Method: "GET", Port: 80, Uri: "/aa", UriMatching: "exact", ContentID: 42},
		{ID: 2, AppID: 1, Method: "GET", Port: 80, Uri: "/bb", UriMatching: "exact", ContentID: 42},
		{ID: 3, AppID: 2, Method: "GET", Port: 80, Uri: "/bb", UriMatching: "exact", ContentID: 42},
	}

	myTestIP := "1.2.3.4"
	session := models.NewSession()
	matchedRule, _ := GetMatchedRule(bunchOfRules, &models.Request{
		Uri:      "/aa",
		Method:   "GET",
		Port:     80,
		SourceIP: myTestIP,
	}, session)

	assert.Equal(t, int64(1), matchedRule.ID)
	session.ServedRuleWithContent(matchedRule.ID, matchedRule.ContentID)
	session.LastRuleServed = matchedRule

	// The path of the next request matches two rules. We expect rule 2 to be
	// served though because it shares the app ID of the rule that was already
	// served.
	matchedRule, _ = GetMatchedRule(bunchOfRules, &models.Request{
		Uri:      "/bb",
		Method:   "GET",
		Port:     80,
		SourceIP: myTestIP,
	}, session)

	assert.Equal(t, int64(2), matchedRule.ID)
	session.ServedRuleWithContent(matchedRule.ID, matchedRule.ContentID)
	session.LastRuleServed = matchedRule

	// Again this matches two rules. However one of them is already served once
	// and this is kept track off. Therefore we expect the rule that was not
	// served before.
	matchedRule, _ = GetMatchedRule(bunchOfRules, &models.Request{
		Uri:      "/bb",
		Method:   "GET",
		Port:     80,
		SourceIP: myTestIP,
	}, session)

	assert.Equal(t, int64(3), matchedRule.ID)
}

func TestGetMatchedRulePortPrioritization(t *testing.T) {
	// Create test rules with and without ports
	rules := []models.ContentRule{
		{
			ID:          44,
			Uri:         "/test",
			Method:      "GET",
			UriMatching: "exact",
			AppID:       66,
		},
		{
			ID:          45,
			Uri:         "/test",
			Method:      "GET",
			Ports:       pgtype.FlatArray[int]{80, 443},
			UriMatching: "exact",
			AppID:       65,
		},
	}

	req := &models.Request{
		ID:       123,
		Method:   "GET",
		Uri:      "/test",
		SourceIP: "192.168.1.1",
		Port:     80,
	}

	// Create session and server
	sess := models.NewSession()

	// Test that rule with ports gets priority
	matchedRule, err := GetMatchedRule(rules, req, sess)
	require.NoError(t, err)
	assert.Equal(t, int64(45), matchedRule.ID, "Expected rule with ports (ID 45) to be matched")

	// Mark rule with ports as served
	sess.ServedRuleWithContent(45, matchedRule.ContentID)

	// Test that rule without ports is selected when rule with ports is served
	matchedRule, err = GetMatchedRule(rules, req, sess)
	require.NoError(t, err)
	assert.Equal(t, int64(44), matchedRule.ID, "Expected rule without ports (ID 44) to be matched")
}

func TestGetMatchedRuleAllowFromNet(t *testing.T) {
	validCIDR := "192.168.1.0/24"
	invalidCIDR := "not-a-cidr"
	differentCIDR := "10.0.0.0/8"

	for _, tc := range []struct {
		name          string
		allowFromNet  *string
		sourceIP      string
		expectMatched bool
	}{
		{"nil AllowFromNet matches any IP", nil, "1.2.3.4", true},
		{"valid CIDR matches IP in range", &validCIDR, "192.168.1.100", true},
		{"valid CIDR does not match IP outside range", &validCIDR, "10.0.0.1", false},
		{"invalid CIDR skips rule", &invalidCIDR, "192.168.1.100", false},
		{"different CIDR does not match", &differentCIDR, "192.168.1.100", false},
		{"different CIDR matches IP in its range", &differentCIDR, "10.5.5.5", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := []models.ContentRule{
				{
					ID:           1,
					AppID:        1,
					Method:       "GET",
					Uri:          "/test",
					UriMatching:  "exact",
					AllowFromNet: tc.allowFromNet,
				},
			}

			req := &models.Request{
				ID:       123,
				Method:   "GET",
				Uri:      "/test",
				Port:     80,
				SourceIP: tc.sourceIP,
			}

			matchedRule, err := GetMatchedRule(rules, req, models.NewSession())

			if tc.expectMatched {
				require.NoError(t, err)
				assert.Equal(t, int64(1), matchedRule.ID)
			} else {
				assert.Error(t, err)
				assert.Equal(t, int64(0), matchedRule.ID)
			}
		})
	}
}

func TestGetMatchedRuleValidUntil(t *testing.T) {
	pastTime := time.Now().Add(-1 * time.Hour)
	futureTime := time.Now().Add(1 * time.Hour)

	for _, tc := range []struct {
		name          string
		validUntil    *time.Time
		expectMatched bool
	}{
		{"nil ValidUntil matches", nil, true},
		{"past ValidUntil skipped", &pastTime, false},
		{"future ValidUntil matches", &futureTime, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := []models.ContentRule{
				{
					ID:          1,
					AppID:       1,
					Method:      "GET",
					Uri:         "/test",
					UriMatching: "exact",
					ValidUntil:  tc.validUntil,
				},
			}

			req := &models.Request{
				Method: "GET",
				Uri:    "/test",
				Port:   80,
			}

			matchedRule, err := GetMatchedRule(rules, req, models.NewSession())

			if tc.expectMatched {
				require.NoError(t, err)
				assert.Equal(t, int64(1), matchedRule.ID)
			} else {
				assert.Error(t, err)
				assert.Equal(t, int64(0), matchedRule.ID)
			}
		})
	}
}
