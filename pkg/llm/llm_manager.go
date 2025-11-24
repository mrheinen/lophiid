// Lophiid distributed honeypot
// Copyright (C) 2025 Niels Heinen
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
	"context"
	"fmt"
	"log/slog"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"sync"
	"time"

	"github.com/sourcegraph/conc/pool"
)

// LLMResult contains the output of an LLM operation and metadata
type LLMResult struct {
	Output    string
	FromCache bool
}

// LLMManagerInterface defines the interface for LLM operations
type LLMManagerInterface interface {
	Complete(prompt string, cacheResult bool) (LLMResult, error)
	CompleteMultiple(prompts []string, cacheResult bool) (map[string]LLMResult, error)
	CompleteWithMessages(msgs []LLMMessage, cacheResult bool) (LLMResult, error)
	CompleteWithTools(msgs []LLMMessage, tools []LLMTool, cacheResult bool) (LLMResult, error)
	SetResponseSchemaFromObject(obj any, title string)
	LoadedModel() string
}

// LLMManager wraps an LLMClient and caches the prompts and responses.
type LLMManager struct {
	client            LLMClient
	pCache            *util.StringMapCache[string]
	metrics           *LLMMetrics
	completionTimeout time.Duration
	promptPrefix      string
	promptSuffix      string
	multiplePoolSize  int
	stripThinking     bool
}

func NewLLMManager(client LLMClient, pCache *util.StringMapCache[string], metrics *LLMMetrics, completionTimeout time.Duration, poolSize int, stripThinking bool, promptPrefix string, promptSuffix string) *LLMManager {
	return &LLMManager{
		client:            client,
		pCache:            pCache,
		metrics:           metrics,
		completionTimeout: completionTimeout,
		multiplePoolSize:  poolSize,
		promptPrefix:      promptPrefix,
		promptSuffix:      promptSuffix,
		stripThinking:     stripThinking,
	}
}

// CreateCacheKeyFromMessages creates a cache key based on the LLM messages
func CreateCacheKeyFromMessages(msgs []LLMMessage) string {
	ret := ""
	for _, msg := range msgs {
		tmpHash := util.FastCacheHash(msg.Content)
		ret = ret + string(tmpHash)
	}

	return ret
}

func (l *LLMManager) getPromptFromCache(prompt string) (string, error) {
	entry, err := l.pCache.Get(prompt)
	if err != nil {
		l.metrics.llmCacheHits.WithLabelValues(constants.LLMCacheMiss).Inc()
		return "", err
	} else {
		l.metrics.llmCacheHits.WithLabelValues(constants.LLMCacheHit).Inc()
	}
	return *entry, nil
}

func (l *LLMManager) LoadedModel() string {
	return l.client.LoadedModel()
}

func (l *LLMManager) SetResponseSchemaFromObject(obj any, title string) {
	l.client.SetResponseSchemaFromObject(obj, title)
}

// CompleteMultiple completes multiple prompts in parallel. It will return a map
func (l *LLMManager) CompleteMultiple(prompts []string, cacheResult bool) (map[string]LLMResult, error) {
	type resultTuple struct {
		prompt string
		result LLMResult
	}
	resultsChan := make(chan resultTuple, len(prompts))

	p := pool.New().WithErrors().WithMaxGoroutines(l.multiplePoolSize)

	for _, prompt := range prompts {
		p.Go(func() error {
			localPrompt := prompt
			ret, err := l.Complete(localPrompt, cacheResult)
			if err != nil {
				return err
			}

			resultsChan <- resultTuple{prompt: localPrompt, result: ret}
			return nil
		})
	}

	err := p.Wait()
	close(resultsChan)

	finalResult := make(map[string]LLMResult, len(prompts))
	for res := range resultsChan {
		finalResult[res.prompt] = res.result
	}

	return finalResult, err
}

func (l *LLMManager) Complete(prompt string, cacheResult bool) (LLMResult, error) {
	entry, err := l.getPromptFromCache(prompt)
	if err == nil {
		return LLMResult{Output: entry, FromCache: true}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), l.completionTimeout)
	defer cancel()

	start := time.Now()
	retStr, err := l.client.Complete(ctx, fmt.Sprintf("%s%s%s", l.promptPrefix, prompt, l.promptSuffix))

	if err != nil {
		slog.Error("error completing prompt", slog.String("prompt", prompt), slog.String("error", err.Error()))
		l.metrics.llmErrorCount.Inc()
		return LLMResult{}, fmt.Errorf("error completing prompt: %w", err)
	}

	l.metrics.llmQueryResponseTime.Observe(time.Since(start).Seconds())

	if l.stripThinking {
		retStr = util.RemoveThinkingFromResponse(retStr)
	}

	if cacheResult {
		l.pCache.Store(prompt, retStr)
	}

	return LLMResult{Output: retStr, FromCache: false}, nil
}

func (l *LLMManager) CompleteWithMessages(msgs []LLMMessage, cacheResult bool) (LLMResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), l.completionTimeout)
	defer cancel()

	cacheKey := CreateCacheKeyFromMessages(msgs)
	entry, err := l.getPromptFromCache(cacheKey)
	if err == nil {
		return LLMResult{Output: entry, FromCache: true}, nil
	}

	start := time.Now()
	retStr, err := l.client.CompleteWithMessages(ctx, msgs)

	if err != nil {
		l.metrics.llmErrorCount.Inc()
		return LLMResult{}, fmt.Errorf("error completing prompt: %w", err)
	}

	l.metrics.llmQueryResponseTime.Observe(time.Since(start).Seconds())

	if l.stripThinking {
		retStr = util.RemoveThinkingFromResponse(retStr)
	}

	if cacheResult {
		l.pCache.Store(cacheKey, retStr)
	}

	return LLMResult{Output: retStr, FromCache: false}, nil
}

func (l *LLMManager) CompleteWithTools(msgs []LLMMessage, tools []LLMTool, cacheResult bool) (LLMResult, error) {
	cacheKey := CreateCacheKeyFromMessages(msgs)
	entry, err := l.getPromptFromCache(cacheKey)
	if err == nil {
		return LLMResult{Output: entry, FromCache: true}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), l.completionTimeout)
	defer cancel()

	start := time.Now()
	retStr, err := l.client.CompleteWithTools(ctx, msgs, tools)

	if err != nil {
		l.metrics.llmErrorCount.Inc()
		return LLMResult{}, fmt.Errorf("error completing prompt with tools: %w", err)
	}

	l.metrics.llmQueryResponseTime.Observe(time.Since(start).Seconds())

	if l.stripThinking {
		retStr = util.RemoveThinkingFromResponse(retStr)
	}

	if cacheResult {
		l.pCache.Store(cacheKey, retStr)
	}

	return LLMResult{Output: retStr, FromCache: false}, nil
}

// DualLLMManager manages primary and secondary LLM clients with fallback functionality
type DualLLMManager struct {
	primary          LLMManagerInterface
	secondary        LLMManagerInterface
	fallbackInterval time.Duration
	lastFailureTime  time.Time
	usingSecondary   bool
	mutex            sync.RWMutex
}

// NewDualLLMManager creates a new DualLLMManager with the specified fallback interval
func NewDualLLMManager(primary, secondary LLMManagerInterface, fallbackInterval time.Duration) *DualLLMManager {
	return &DualLLMManager{
		primary:          primary,
		secondary:        secondary,
		fallbackInterval: fallbackInterval,
		usingSecondary:   false,
	}
}

func (d *DualLLMManager) SetResponseSchemaFromObject(obj any, title string) {
	d.primary.SetResponseSchemaFromObject(obj, title)
	d.secondary.SetResponseSchemaFromObject(obj, title)
}

// Complete attempts to complete a single prompt using the primary client, falls back to secondary on error
func (d *DualLLMManager) Complete(prompt string, cacheResult bool) (LLMResult, error) {
	d.mutex.Lock()
	// Check if we should switch back to primary after fallback interval
	if d.usingSecondary && time.Since(d.lastFailureTime) > d.fallbackInterval {
		slog.Info("Switching back to primary LLM client after fallback interval")
		d.usingSecondary = false
	}
	usingSecondary := d.usingSecondary
	d.mutex.Unlock()

	if !usingSecondary {
		result, err := d.primary.Complete(prompt, cacheResult)
		if err == nil {
			return result, nil
		}

		// Primary failed, switch to secondary
		slog.Error("Primary LLM client failed, switching to secondary", slog.String("error", err.Error()))
		d.mutex.Lock()
		d.usingSecondary = true
		d.lastFailureTime = time.Now()
		d.mutex.Unlock()
	}

	// Use secondary client
	slog.Info("Using secondary LLM client", slog.Bool("fallback_mode", usingSecondary))
	result, err := d.secondary.Complete(prompt, cacheResult)
	if err != nil {
		return LLMResult{}, fmt.Errorf("both primary and secondary LLM clients failed: %w", err)
	}

	return result, nil
}

func (d *DualLLMManager) CompleteWithMessages(msgs []LLMMessage, cacheResult bool) (LLMResult, error) {
	d.mutex.Lock()
	// Check if we should switch back to primary after fallback interval
	if d.usingSecondary && time.Since(d.lastFailureTime) > d.fallbackInterval {
		slog.Info("Switching back to primary LLM client after fallback interval")
		d.usingSecondary = false
	}
	usingSecondary := d.usingSecondary
	d.mutex.Unlock()

	if !usingSecondary {
		result, err := d.primary.CompleteWithMessages(msgs, cacheResult)
		if err == nil {
			return result, nil
		}

		// Primary failed, switch to secondary
		slog.Error("Primary LLM client failed, switching to secondary", slog.String("error", err.Error()))
		d.mutex.Lock()
		d.usingSecondary = true
		d.lastFailureTime = time.Now()
		d.mutex.Unlock()
	}

	// Use secondary client
	slog.Info("Using secondary LLM client", slog.Bool("fallback_mode", usingSecondary))
	result, err := d.secondary.CompleteWithMessages(msgs, cacheResult)
	if err != nil {
		return LLMResult{}, fmt.Errorf("both primary and secondary LLM clients failed: %w", err)
	}

	return result, nil
}

func (d *DualLLMManager) CompleteWithTools(msgs []LLMMessage, tools []LLMTool, cacheResult bool) (LLMResult, error) {
	d.mutex.Lock()
	// Check if we should switch back to primary after fallback interval
	if d.usingSecondary && time.Since(d.lastFailureTime) > d.fallbackInterval {
		slog.Info("Switching back to primary LLM client after fallback interval")
		d.usingSecondary = false
	}
	usingSecondary := d.usingSecondary
	d.mutex.Unlock()

	if !usingSecondary {
		result, err := d.primary.CompleteWithTools(msgs, tools, cacheResult)
		if err == nil {
			return result, nil
		}

		// Primary failed, switch to secondary
		slog.Error("Primary LLM client failed, switching to secondary", slog.String("error", err.Error()))
		d.mutex.Lock()
		d.usingSecondary = true
		d.lastFailureTime = time.Now()
		d.mutex.Unlock()
	}

	// Use secondary client
	slog.Info("Using secondary LLM client", slog.Bool("fallback_mode", usingSecondary))
	result, err := d.secondary.CompleteWithTools(msgs, tools, cacheResult)
	if err != nil {
		return LLMResult{}, fmt.Errorf("both primary and secondary LLM clients failed: %w", err)
	}

	return result, nil
}

// CompleteMultiple attempts to complete prompts using the primary client, falls back to secondary on error
func (d *DualLLMManager) CompleteMultiple(prompts []string, cacheResult bool) (map[string]LLMResult, error) {

	d.mutex.Lock()
	// Check if we should switch back to primary after fallback interval
	if d.usingSecondary && time.Since(d.lastFailureTime) > d.fallbackInterval {
		slog.Info("Switching back to primary LLM client after fallback interval")
		d.usingSecondary = false
	}

	usingSecondary := d.usingSecondary
	d.mutex.Unlock()

	// Try primary client first (unless we're in fallback mode)
	if !usingSecondary {
		result, err := d.primary.CompleteMultiple(prompts, cacheResult)
		if err == nil {
			return result, nil
		}

		// Primary failed, switch to secondary
		slog.Error("Primary LLM client failed, switching to secondary", slog.String("error", err.Error()))
		d.mutex.Lock()
		d.usingSecondary = true
		d.lastFailureTime = time.Now()
		d.mutex.Unlock()
	}

	// Use secondary client
	slog.Info("Using secondary LLM client", slog.Bool("fallback_mode", usingSecondary))
	result, err := d.secondary.CompleteMultiple(prompts, cacheResult)
	if err != nil {
		return nil, fmt.Errorf("both primary and secondary LLM clients failed: %w", err)
	}

	return result, nil
}

// LoadedModel returns the model name of the currently active client
func (d *DualLLMManager) LoadedModel() string {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	if d.usingSecondary {
		return fmt.Sprintf("%s (secondary)", d.secondary.LoadedModel())
	}
	return d.primary.LoadedModel()
}
