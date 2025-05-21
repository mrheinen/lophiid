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
	"errors"
	"lophiid/pkg/util"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestComplete(t *testing.T) {
	testCompletionString := "completion"
	client := MockLLMClient{CompletionToReturn: testCompletionString, ErrorToReturn: nil}
	pCache := util.NewStringMapCache[string]("", time.Second)
	pReg := prometheus.NewRegistry()

	metrics := CreateLLMMetrics(pReg)

	lm := NewLLMManager(&client, pCache, metrics, time.Hour, 5, false, "", "")
	res, err := lm.Complete("aaaa", true)

	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if res != testCompletionString {
		t.Errorf("expected %s, got %s", testCompletionString, res)
	}
}

func TestCompleteWithPrefix(t *testing.T) {
	testPrefix := "PREFIX"
	testCompletionString := "completion"
	client := MockLLMClient{CompletionToReturn: testCompletionString, ErrorToReturn: nil}
	pCache := util.NewStringMapCache[string]("", time.Second)
	pReg := prometheus.NewRegistry()

	metrics := CreateLLMMetrics(pReg)

	lm := NewLLMManager(&client, pCache, metrics, time.Hour, 5, false, testPrefix, "")
	res, err := lm.Complete("aaaa", true)

	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if res != testCompletionString {
		t.Errorf("expected %s, got %s", testCompletionString, res)
	}

	if !strings.HasPrefix(client.LastReceivedPrompt, testPrefix) {
		t.Errorf("expected prompt to start with %s, got %s", testPrefix, client.LastReceivedPrompt)
	}
}
func TestCompleteWithSuffix(t *testing.T) {
	testSuffix := "SUFFIX"
	testCompletionString := "completion"
	client := MockLLMClient{CompletionToReturn: testCompletionString, ErrorToReturn: nil}
	pCache := util.NewStringMapCache[string]("", time.Second)
	pReg := prometheus.NewRegistry()

	metrics := CreateLLMMetrics(pReg)

	lm := NewLLMManager(&client, pCache, metrics, time.Hour, 5, false, "", testSuffix)
	res, err := lm.Complete("aaaa", true)

	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if res != testCompletionString {
		t.Errorf("expected %s, got %s", testCompletionString, res)
	}

	if !strings.HasSuffix(client.LastReceivedPrompt, testSuffix) {
		t.Errorf("expected prompt to start with %s, got %s", testSuffix, client.LastReceivedPrompt)
	}
}

func TestCompleteErrorCounted(t *testing.T) {
	testCompletionString := "completion"
	client := MockLLMClient{CompletionToReturn: testCompletionString, ErrorToReturn: errors.New("beh")}
	pCache := util.NewStringMapCache[string]("", time.Second)
	pReg := prometheus.NewRegistry()

	metrics := CreateLLMMetrics(pReg)

	lm := NewLLMManager(&client, pCache, metrics, time.Hour, 5, false, "", "")
	_, err := lm.Complete("aaaa", true)

	if err == nil {
		t.Errorf("expected error")
	}

	count := testutil.ToFloat64(metrics.llmErrorCount)
	if count != 1 {
		t.Errorf("expected 1 error, got %f", count)
	}
}

func TestCompleteMultiple(t *testing.T) {
	testCompletionString := "completion"
	client := MockLLMClient{CompletionToReturn: testCompletionString, ErrorToReturn: nil}
	pCache := util.NewStringMapCache[string]("", time.Second)
	pReg := prometheus.NewRegistry()

	metrics := CreateLLMMetrics(pReg)
	lm := NewLLMManager(&client, pCache, metrics, time.Hour, 5, false, "", "")

	prompts := []string{"aaaa", "bbbb"}
	resMap, err := lm.CompleteMultiple(prompts, true)

	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if len(resMap) != 2 {
		t.Errorf("expected 2 results, got %d", len(resMap))
	}

	for _, p := range prompts {
		if resMap[p] != testCompletionString {
			t.Errorf("expected %s, got %s", testCompletionString, resMap[p])
		}
	}
}

func TestCompleteWithStripThinking(t *testing.T) {
	// Create a response with thinking tags that should be stripped
	responseWithThinking := "I'm thinking about this...\n</think>\nHere is the actual response"
	expectedResult := "Here is the actual response"

	// Create separate cache and clients for each test to avoid interference
	// Client for testing with stripThinking=true
	clientWithStrip := MockLLMClient{CompletionToReturn: responseWithThinking, ErrorToReturn: nil}
	pCacheWithStrip := util.NewStringMapCache[string]("", time.Second)
	pReg := prometheus.NewRegistry()
	metrics := CreateLLMMetrics(pReg)

	// Create an LLMManager with stripThinking set to true
	lm := NewLLMManager(&clientWithStrip, pCacheWithStrip, metrics, time.Hour, 5, true, "", "")
	res, err := lm.Complete("test prompt", true)

	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	// Verify that the thinking section was removed
	if res != expectedResult {
		t.Errorf("expected %q after stripping thinking, got %q", expectedResult, res)
	}

	// Create a separate client for testing without stripping thinking
	clientNoStrip := MockLLMClient{CompletionToReturn: responseWithThinking, ErrorToReturn: nil}
	pCacheNoStrip := util.NewStringMapCache[string]("", time.Second)
	
	// Create an LLMManager with stripThinking set to false
	lmNoStrip := NewLLMManager(&clientNoStrip, pCacheNoStrip, metrics, time.Hour, 5, false, "", "")
	resNoStrip, _ := lmNoStrip.Complete("test prompt", true)

	// Verify that the thinking section was preserved
	if resNoStrip != responseWithThinking {
		t.Errorf("expected original response %q when not stripping thinking, got %q", responseWithThinking, resNoStrip)
	}
}
