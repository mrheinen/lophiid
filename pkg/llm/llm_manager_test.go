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
package llm

import (
	"lophiid/pkg/util"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestComplete(t *testing.T) {
	testCompletionString := "completion"
	client := MockLLMClient{CompletionToReturn: testCompletionString, ErrorToReturn: nil}
	pCache := util.NewStringMapCache[string]("", time.Second)
	pReg := prometheus.NewRegistry()

	metrics := CreateLLMMetrics(pReg)

	lm := NewLLMManager(&client, pCache, metrics, time.Hour)
	res, err := lm.Complete("aaaa")

	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if res != testCompletionString {
		t.Errorf("expected %s, got %s", testCompletionString, res)
	}
}
