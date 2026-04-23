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
package tools

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterLinks_Empty(t *testing.T) {
	assert.Empty(t, filterLinks(nil, 5, 20))
	assert.Empty(t, filterLinks([]string{}, 5, 20))
}

func TestFilterLinks_TotalCap(t *testing.T) {
	links := []string{
		"https://example.com/1",
		"https://example.com/2",
		"https://example.com/3",
	}
	got := filterLinks(links, 10, 2)
	assert.Len(t, got, 2)
	assert.Equal(t, links[:2], got)
}

func TestFilterLinks_PerDomainCap(t *testing.T) {
	links := []string{
		"https://github.com/a",
		"https://github.com/b",
		"https://github.com/c",
		"https://exploit-db.com/1",
	}
	got := filterLinks(links, 2, 20)
	assert.Len(t, got, 3)
	assert.Equal(t, "https://github.com/a", got[0])
	assert.Equal(t, "https://github.com/b", got[1])
	assert.Equal(t, "https://exploit-db.com/1", got[2])
}

func TestFilterLinks_PerDomainAndTotalCap(t *testing.T) {
	links := []string{
		"https://github.com/a",
		"https://github.com/b",
		"https://github.com/c",
		"https://exploit-db.com/1",
		"https://exploit-db.com/2",
		"https://nvd.nist.gov/1",
	}
	got := filterLinks(links, 2, 4)
	assert.Len(t, got, 4)
	assert.Contains(t, got, "https://github.com/a")
	assert.Contains(t, got, "https://github.com/b")
	assert.NotContains(t, got, "https://github.com/c")
	assert.Contains(t, got, "https://exploit-db.com/1")
	assert.Contains(t, got, "https://exploit-db.com/2")
	assert.NotContains(t, got, "https://nvd.nist.gov/1")
}

func TestFilterLinks_MalformedURLsDropped(t *testing.T) {
	links := []string{
		"not-a-url",
		"://broken",
		"https://valid.example.com/page",
	}
	got := filterLinks(links, 5, 20)
	assert.Len(t, got, 1)
	assert.Equal(t, "https://valid.example.com/page", got[0])
}

func TestFilterLinks_SubdomainsCountedSeparately(t *testing.T) {
	links := []string{
		"https://raw.githubusercontent.com/a",
		"https://raw.githubusercontent.com/b",
		"https://gist.githubusercontent.com/x",
	}
	got := filterLinks(links, 1, 20)
	assert.Len(t, got, 2)
	assert.Contains(t, got, "https://raw.githubusercontent.com/a")
	assert.NotContains(t, got, "https://raw.githubusercontent.com/b")
	assert.Contains(t, got, "https://gist.githubusercontent.com/x")
}

func TestFilterLinks_AllowsUpToLimit(t *testing.T) {
	links := make([]string, 10)
	for i := range links {
		links[i] = "https://unique-host-" + string(rune('a'+i)) + ".com/page"
	}
	got := filterLinks(links, 1, 5)
	assert.Len(t, got, 5)
}
