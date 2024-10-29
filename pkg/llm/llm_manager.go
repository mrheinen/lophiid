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
	"context"
	"fmt"
	"log/slog"
	"lophiid/pkg/util"
	"time"

	"github.com/sourcegraph/conc/pool"
)

// LLMManager wraps an LLMClient and caches the prompts and responses.
type LLMManager struct {
	client            LLMClient
	pCache            *util.StringMapCache[string]
	metrics           *LLMMetrics
	completionTimeout time.Duration
	multiplePoolSize  int
}

func NewLLMManager(client LLMClient, pCache *util.StringMapCache[string], metrics *LLMMetrics, completionTimeout time.Duration, poolSize int) *LLMManager {
	return &LLMManager{
		client:            client,
		pCache:            pCache,
		metrics:           metrics,
		completionTimeout: completionTimeout,
		multiplePoolSize:  poolSize,
	}
}

// CompleteMultiple completes multiple prompts in parallel. It will return a map
func (l *LLMManager) CompleteMultiple(prompts []string) (map[string]string, error) {
    var result sync.Map
    p := pool.New().WithErrors().WithMaxGoroutines(l.multiplePoolSize)

    for _, prompt := range prompts {
        p.Go(func() error {
            localPrompt := prompt
            ret, err := l.Complete(localPrompt)
            if err != nil {
                return err
            }

            result.Store(localPrompt, ret)
            return nil
        })
    }

    err := p.Wait()

    finalResult := make(map[string]string)
    result.Range(func(key, value interface{}) bool {
        finalResult[key.(string)] = value.(string)
        return true
    })

    return finalResult, err
}

func (l *LLMManager) Complete(prompt string) (string, error) {
	entry, err := l.pCache.Get(prompt)
	if err == nil {
		return *entry, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), l.completionTimeout)
	defer cancel()

	start := time.Now()
	retStr, err := l.client.Complete(ctx, prompt)

	if err != nil {
		slog.Error("error completing prompt", slog.String("prompt", prompt), slog.String("error", err.Error()))
		l.metrics.llmErrorCount.Inc()
		return "", fmt.Errorf("error completing prompt: %w", err)
	}

	l.metrics.llmQueryResponseTime.Observe(time.Since(start).Seconds())
	l.pCache.Store(prompt, retStr)

	return retStr, nil
}
