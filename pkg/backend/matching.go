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
	"fmt"
	"log/slog"
	"lophiid/pkg/database/models"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"time"
)

func MatchesString(method string, dataToSearch string, searchValue string) bool {
	if searchValue == "" {
		return false
	}

	switch method {
	case "exact":
		return dataToSearch == searchValue
	case "prefix":
		return strings.HasPrefix(dataToSearch, searchValue)
	case "suffix":
		return strings.HasSuffix(dataToSearch, searchValue)
	case "contains":
		return strings.Contains(dataToSearch, searchValue)
	case "regex":
		matched, err := regexp.MatchString(searchValue, dataToSearch)
		// Most cases should be caught when validating a contentrule upon
		// creation.
		if err != nil {
			slog.Warn("Invalid regex", slog.String("error", err.Error()))
			return false
		}
		return matched
	default:
		return false
	}
}

func GetMatchedRule(rules []models.ContentRule, req *models.Request, session *models.Session) (models.ContentRule, error) {
	matchedPriority1 := []models.ContentRule{}
	matchedPriority2 := []models.ContentRule{}

	for _, rule := range rules {
		// Exclude rules that are expired.
		if rule.ValidUntil != nil && time.Now().After(*rule.ValidUntil) {
			slog.Debug("rule is nolonger valid", slog.Int64("request_id", req.ID), slog.Int64("session_id", session.ID), slog.Int64("rule_id", rule.ID))
			continue
		}

		if rule.AllowFromNet != nil {
			_, ipNet, err := net.ParseCIDR(*rule.AllowFromNet)
			if err != nil {
				slog.Error("invalid rule network", slog.Int64("request_id", req.ID), slog.Int64("session_id", session.ID), slog.Int64("rule_id", rule.ID), slog.String("network", *rule.AllowFromNet), slog.String("error", err.Error()))
				continue
			}

			if !ipNet.Contains(net.ParseIP(req.SourceIP)) {
				slog.Error("request not allowed from network", slog.Int64("request_id", req.ID), slog.Int64("session_id", session.ID), slog.Int64("rule_id", rule.ID), slog.String("network", *rule.AllowFromNet))
				continue
			}
		}

		if len(rule.Ports) != 0 {
			found := false
			for _, port := range rule.Ports {
				if int64(port) == req.Port {
					found = true
					break
				}
			}

			// This means ports were specified but none matched the request. In that
			// case we can continue the search.
			if !found {
				continue
			}
		}

		if rule.Method != "ANY" && rule.Method != req.Method {
			continue
		}

		matchedUri := MatchesString(rule.UriMatching, req.Uri, rule.Uri)
		matchedBody := MatchesString(rule.BodyMatching, string(req.Body), rule.Body)

		// We assume here that at least path or body are set.
		if matchedUri && rule.Body == "" {
			matchedPriority1 = append(matchedPriority1, rule)
		} else if matchedBody && rule.Uri == "" {
			matchedPriority1 = append(matchedPriority1, rule)
		} else if matchedBody && matchedUri {
			matchedPriority2 = append(matchedPriority2, rule)
		}
	}

	// This is important. If there are rules that have more matching criteria
	// then we will take these rules and serve them first.
	var matchedRules []models.ContentRule
	if len(matchedPriority2) > 0 {
		matchedRules = matchedPriority2
	} else {
		matchedRules = matchedPriority1
	}

	if len(matchedRules) == 0 {
		return models.ContentRule{}, fmt.Errorf("no rule found")
	}

	if len(matchedRules) == 1 {
		return matchedRules[0], nil
	}

	var unservedRules []models.ContentRule
	// Find out what rules match but haven't been served.
	for _, r := range matchedRules {
		if !session.HasServedRule(r.ID) {
			unservedRules = append(unservedRules, r)
			// A rule matching the same app id is prefered.
			if r.AppID == session.LastRuleServed.AppID {
				return r, nil
			}
		}
	}

	var matchedRule models.ContentRule
	if len(unservedRules) > 0 {
		// Rules with ports get priority.
		foundPortRule := false
		for _, rule := range unservedRules {
			if len(rule.Ports) > 0 {
				foundPortRule = true
				matchedRule = rule
				break
			}
		}

		if !foundPortRule {
			matchedRule = unservedRules[rand.Intn(len(unservedRules))]
		}

	} else {
		// In this case all rule content combinations have been served at least
		// once to this target. We send a random one.
		matchedRule = matchedRules[rand.Intn(len(matchedRules))]
	}

	return matchedRule, nil
}
