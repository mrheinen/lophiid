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
package killchain

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"sync/atomic"
	"time"

	"lophiid/pkg/backend/rules"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"lophiid/pkg/util/constants"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/sourcegraph/conc/pool"
)

// KillChainLLMPhase represents a single detected kill chain phase in the LLM response.
type KillChainLLMPhase struct {
	Phase          string `json:"phase" jsonschema_description:"The kill chain phase. Must be exactly one of: RECON, VERIFY, EXPLOITATION, CLEANUP, UNKNOWN."`
	Evidence       string `json:"evidence" jsonschema_description:"A concise explanation of which requests and behaviours indicate this phase."`
	FirstRequestID int64  `json:"first_request_id" jsonschema_description:"The Request ID of the first request that belongs to this phase."`
	LastRequestID  int64  `json:"last_request_id" jsonschema_description:"The Request ID of the last request that belongs to this phase."`
	RequestCount   int64  `json:"request_count" jsonschema_description:"The number of requests that belong to this phase."`
}

// KillChainLLMChain represents a single distinct kill chain identified by the LLM.
type KillChainLLMChain struct {
	RequestIDs []int64             `json:"request_ids" jsonschema_description:"The IDs of every request that belongs to this kill chain."`
	Phases     []KillChainLLMPhase `json:"phases" jsonschema_description:"The kill chain phases detected within this chain."`
}

// phaseDepthOrdinal maps a kill chain phase string to its depth ordinal.
// Unknown/unmapped phases return 0.
func phaseDepthOrdinal(phase string) int64 {
	switch phase {
	case constants.KillChainPhaseRecon:
		return constants.KillChainPhaseDepthRecon
	case constants.KillChainPhaseVerify:
		return constants.KillChainPhaseDepthVerify
	case constants.KillChainPhaseExploitation:
		return constants.KillChainPhaseDepthExploitation
	case constants.KillChainPhaseCleanup:
		return constants.KillChainPhaseDepthCleanup
	default:
		return 0
	}
}

// KillChainLLMResult is the structured output expected from the LLM.
type KillChainLLMResult struct {
	KillChains []KillChainLLMChain `json:"kill_chains" jsonschema_description:"The list of distinct kill chains identified in the session. Empty if none were found."`
}

// KillChainAnalyzer analyses completed sessions for kill chain phases using an LLM.
type KillChainAnalyzer struct {
	dbClient       database.DatabaseClient
	llmManager     llm.LLMManagerInterface
	safeRules      *rules.SafeRules
	maxRequests    int
	maxRequestSize int
	concurrency    int
	dryRun         bool
}

// NewKillChainAnalyzer creates a new KillChainAnalyzer.
// safeRules may be nil; when provided it is used to annotate requests with their
// matched rule's RequestPurpose without any additional database queries.
func NewKillChainAnalyzer(dbClient database.DatabaseClient, llmManager llm.LLMManagerInterface, safeRules *rules.SafeRules, maxRequests int, maxRequestSize int, concurrency int, dryRun bool) (*KillChainAnalyzer, error) {
	a := &KillChainAnalyzer{
		dbClient:       dbClient,
		llmManager:     llmManager,
		safeRules:      safeRules,
		maxRequests:    maxRequests,
		maxRequestSize: maxRequestSize,
		concurrency:    concurrency,
		dryRun:         dryRun,
	}
	if err := llmManager.SetResponseSchemaFromObject(KillChainLLMResult{}, "KillChainLLMResult"); err != nil {
		return nil, fmt.Errorf("setting LLM response schema: %w", err)
	}
	return a, nil
}

// AnalyzeSessions fetches up to batchSize PENDING sessions and analyses each one.
// Returns the number of sessions processed and any terminal error.
func (a *KillChainAnalyzer) AnalyzeSessions(batchSize int64) (int64, error) {
	sessions, err := a.dbClient.SearchSession(0, batchSize,
		fmt.Sprintf("active:false kill_chain_process_status:%s", constants.KillChainProcessStatusPending))
	if err != nil {
		return 0, fmt.Errorf("searching sessions: %w", err)
	}

	var processed atomic.Int64
	p := pool.New().WithMaxGoroutines(a.concurrency)
	for i := range sessions {
		i := i
		p.Go(func() {
			if analyzeErr := a.analyzeSession(&sessions[i]); analyzeErr != nil {
				slog.Error("error analysing session",
					slog.Int64("session_id", sessions[i].ID),
					slog.String("error", analyzeErr.Error()))
			}
			processed.Add(1)
		})
	}
	p.Wait()
	return processed.Load(), nil
}

// AnalyzeSingleSession analyses a single session by ID.
func (a *KillChainAnalyzer) AnalyzeSingleSession(sessionID int64) error {
	sessions, err := a.dbClient.SearchSession(0, 1, fmt.Sprintf("id:%d", sessionID))
	if err != nil || len(sessions) == 0 {
		return fmt.Errorf("session %d not found: %w", sessionID, err)
	}
	return a.analyzeSession(&sessions[0])
}

func (a *KillChainAnalyzer) analyzeSession(session *models.Session) error {
	slog.Info("analysing session", slog.Int64("session_id", session.ID))

	// Fetch one more than max to detect the over-limit case.
	requests, err := a.dbClient.SearchRequests(0, int64(a.maxRequests)+1,
		fmt.Sprintf("session_id:%d", session.ID))
	if err != nil {
		return a.markFailed(session, fmt.Errorf("fetching requests: %w", err))
	}

	// reverse the requests so that they are chronologically as indicated by the prompt
	slices.Reverse(requests)
	partial := len(requests) > a.maxRequests
	if partial {
		slog.Info("session exceeds max requests, analysing first N only",
			slog.Int64("session_id", session.ID),
			slog.Int("total_requests", len(requests)),
			slog.Int("analysing", a.maxRequests))
		requests = requests[:a.maxRequests]
	}

	// Build a request map for fast ID lookup.
	reqMap := make(map[int64]models.Request, len(requests))
	for _, r := range requests {
		reqMap[r.ID] = r
	}

	// Build a ruleID→purpose map from the cached rules (no DB query needed).
	rulePurposes := make(map[int64]string)
	if a.safeRules != nil {
		for _, req := range requests {
			if req.RuleID == 0 {
				continue
			}
			if _, seen := rulePurposes[req.RuleID]; seen {
				continue
			}
			if rule, ok := a.safeRules.GetByID(req.RuleID); ok && rule.RequestPurpose != constants.RuleRequestPurposeUnknown {
				rulePurposes[req.RuleID] = rule.RequestPurpose
			}
		}
	}

	msgs := []llm.LLMMessage{
		{Role: constants.LLMClientMessageSystem, Content: killChainSystemPrompt},
		{Role: constants.LLMClientMessageUser, Content: buildUserMessage(requests, a.maxRequestSize, rulePurposes)},
	}

	result, err := a.llmManager.CompleteWithMessages(msgs, false)
	if err != nil {
		return a.markFailed(session, fmt.Errorf("LLM completion: %w", err))
	}

	var llmResult KillChainLLMResult
	if jsonErr := json.Unmarshal([]byte(result.Output), &llmResult); jsonErr != nil {
		return a.markFailed(session, fmt.Errorf("parsing LLM JSON: %w (output: %s)", jsonErr, result.Output))
	}

	modelName := a.llmManager.LoadedModel()

	var chainsInserted int
	var persistErr error
	for _, chain := range llmResult.KillChains {
		// Filter: skip chains with fewer than 2 unique cmp_hash values.
		uniqueCmpHashes := make(map[string]struct{})
		for _, reqID := range chain.RequestIDs {
			if req, ok := reqMap[reqID]; ok {
				uniqueCmpHashes[req.CmpHash] = struct{}{}
			}
		}
		if len(uniqueCmpHashes) < 2 {
			slog.Info("skipping kill chain with fewer than 2 unique cmp_hash values",
				slog.Int64("session_id", session.ID),
				slog.Int("unique_cmp_hashes", len(uniqueCmpHashes)))
			continue
		}

		// Compute startedAt = earliest first_request_time across all phases.
		startedAt := session.StartedAt
		firstSet := false
		for _, p := range chain.Phases {
			if req, ok := reqMap[p.FirstRequestID]; ok {
				if !firstSet || req.TimeReceived.Before(startedAt) {
					startedAt = req.TimeReceived
					firstSet = true
				}
			}
		}

		if a.dryRun {
			chainsInserted++
			continue
		}

		// Collect unique base hashes across all requests in this chain.
		seenChainBaseHashes := make(map[string]struct{})
		var chainUniqueBaseHashes []string
		for _, reqID := range chain.RequestIDs {
			if req, ok := reqMap[reqID]; ok && req.BaseHash != "" {
				if _, seen := seenChainBaseHashes[req.BaseHash]; !seen {
					seenChainBaseHashes[req.BaseHash] = struct{}{}
					chainUniqueBaseHashes = append(chainUniqueBaseHashes, req.BaseHash)
				}
			}
		}

		// Compute depth metrics from the phases returned by the LLM.
		var maxDepth int64
		for _, p := range chain.Phases {
			if d := phaseDepthOrdinal(p.Phase); d > maxDepth {
				maxDepth = d
			}
		}

		var endedAt *time.Time
		for _, p := range chain.Phases {
			if lastReq, ok := reqMap[p.LastRequestID]; ok {
				t := lastReq.TimeReceived
				if endedAt == nil || t.After(*endedAt) {
					endedAt = &t
				}
			}
		}

		kc := &models.KillChain{
			SessionID:        session.ID,
			StartedAt:        startedAt,
			EndedAt:          endedAt,
			UniqueBaseHashes: pgtype.FlatArray[string](chainUniqueBaseHashes),
			SourceModel:      modelName,
			PhaseCount:       int64(len(chain.Phases)),
			MaxPhaseDepth:    maxDepth,
		}
		inserted, insertErr := a.dbClient.Insert(kc)
		if insertErr != nil {
			slog.Error("error inserting kill chain",
				slog.Int64("session_id", session.ID),
				slog.String("error", insertErr.Error()))
			persistErr = insertErr
			continue
		}
		kcID := inserted.(*models.KillChain).ID

		for _, p := range chain.Phases {
			firstReqTime := startedAt
			if req, ok := reqMap[p.FirstRequestID]; ok {
				firstReqTime = req.TimeReceived
			} else {
				slog.Warn("LLM returned unknown first_request_id, falling back to chain start",
					slog.Int64("session_id", session.ID),
					slog.Int64("first_request_id", p.FirstRequestID))
			}

			lastReqTime := firstReqTime
			var durationSecs int64
			if lastReq, ok := reqMap[p.LastRequestID]; ok {
				lastReqTime = lastReq.TimeReceived
				durationSecs = int64(lastReqTime.Sub(firstReqTime).Seconds())
				if durationSecs < 0 {
					durationSecs = 0
				}
			}

			phase := &models.SingleKillChainPhase{
				KillChainID:          kcID,
				SessionID:            session.ID,
				Phase:                p.Phase,
				Evidence:             p.Evidence,
				FirstRequestID:       p.FirstRequestID,
				FirstRequestTime:     firstReqTime,
				LastRequestTime:      lastReqTime,
				RequestCount:         p.RequestCount,
				PhaseDurationSeconds: durationSecs,
				SourceModel:          modelName,
			}
			if _, phaseErr := a.dbClient.Insert(phase); phaseErr != nil {
				slog.Error("error inserting kill chain phase",
					slog.Int64("session_id", session.ID),
					slog.String("phase", p.Phase),
					slog.String("error", phaseErr.Error()))
				persistErr = phaseErr
			}
		}
		chainsInserted++
	}

	if persistErr != nil {
		return a.markFailed(session, fmt.Errorf("persisting kill chain data: %w", persistErr))
	}

	if partial {
		session.KillChainProcessStatus = constants.KillChainProcessStatusPartial
	} else {
		session.KillChainProcessStatus = constants.KillChainProcessStatusDone
	}

	slog.Info("session analysed",
		slog.Int64("session_id", session.ID),
		slog.Int("kill_chains", chainsInserted))

	return a.updateSession(session)
}

func (a *KillChainAnalyzer) markFailed(session *models.Session, cause error) error {
	session.KillChainProcessStatus = constants.KillChainProcessStatusFailed
	if !a.dryRun {
		if updateErr := a.dbClient.Update(session); updateErr != nil {
			slog.Error("error marking session as failed",
				slog.Int64("session_id", session.ID),
				slog.String("error", updateErr.Error()))
		}
	}
	return cause
}

func (a *KillChainAnalyzer) updateSession(session *models.Session) error {
	if a.dryRun {
		return nil
	}
	return a.dbClient.Update(session)
}
