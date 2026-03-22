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
package campaign

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
)

// RunInterval runs the pipeline on a timer in production mode.
func RunInterval(ctx context.Context, pipeline *Pipeline, metrics *PipelineMetrics, scanInterval, lookbackWindow time.Duration) error {
	slog.Info("starting interval mode",
		slog.Duration("scan_interval", scanInterval),
		slog.Duration("lookback_window", lookbackWindow),
	)

	// Run once immediately.
	now := time.Now().UTC()
	windowStart := now.Add(-lookbackWindow)
	runAndRecord(ctx, pipeline, metrics, windowStart, now)

	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("interval mode stopped")
			return ctx.Err()
		case <-ticker.C:
			now := time.Now().UTC()
			windowStart := now.Add(-lookbackWindow)
			runAndRecord(ctx, pipeline, metrics, windowStart, now)
		}
	}
}

// BackfillChunk represents a single chunk of the backfill window.
type BackfillChunk struct {
	Start time.Time
	End   time.Time
}

// ComputeBackfillChunks divides the backfill window into lookback-sized chunks.
func ComputeBackfillChunks(from, to time.Time, lookbackWindow time.Duration) []BackfillChunk {
	var chunks []BackfillChunk
	current := from
	for current.Before(to) {
		end := current.Add(lookbackWindow)
		if end.After(to) {
			end = to
		}
		chunks = append(chunks, BackfillChunk{Start: current, End: end})
		current = end
	}
	return chunks
}

// runAndRecord executes a single pipeline run and records the result in metrics.
func runAndRecord(ctx context.Context, pipeline *Pipeline, metrics *PipelineMetrics, windowStart, windowEnd time.Time) {
	start := time.Now()
	result, err := pipeline.Run(ctx, windowStart, windowEnd)
	duration := time.Since(start).Seconds()

	if err != nil {
		slog.Error("pipeline run failed", slog.String("error", err.Error()))
	}
	if result != nil && metrics != nil {
		metrics.RecordResult(result)
		metrics.PipelineRunSeconds.Observe(duration)
	}
}

// RunBackfill runs the pipeline in backfill mode over the given time window.
func RunBackfill(ctx context.Context, pipeline *Pipeline, metrics *PipelineMetrics, from, to time.Time, lookbackWindow time.Duration) error {
	chunks := ComputeBackfillChunks(from, to, lookbackWindow)
	slog.Info("starting backfill mode",
		slog.Time("from", from),
		slog.Time("to", to),
		slog.Int("chunks", len(chunks)),
	)

	// If --wipe was used, WipeCampaignsInWindow should be called before this
	// function to remove existing campaigns in the window.

	for i, chunk := range chunks {
		slog.Info("processing backfill chunk",
			slog.Int("chunk", i+1),
			slog.Int("total", len(chunks)),
			slog.Time("start", chunk.Start),
			slog.Time("end", chunk.End),
		)

		start := time.Now()
		result, err := pipeline.Run(ctx, chunk.Start, chunk.End)
		duration := time.Since(start).Seconds()

		if result != nil && metrics != nil {
			metrics.RecordResult(result)
			metrics.PipelineRunSeconds.Observe(duration)
		}

		if err != nil {
			return fmt.Errorf("backfill chunk %d failed: %w", i+1, err)
		}

		slog.Info("backfill chunk complete",
			slog.Int("chunk", i+1),
			slog.Int("campaigns_created", result.CampaignsCreated),
			slog.Int("seeds_added", result.SeedsAdded),
		)
	}

	slog.Info("backfill complete")
	return nil
}

// WipeCampaignsInWindow deletes all campaigns whose time range overlaps the
// given [from, to] window. The ON DELETE CASCADE constraint on campaign_request
// automatically removes associated request links. The denormalized campaign_id
// on the request table is also cleared for affected requests.
func WipeCampaignsInWindow(db database.DatabaseClient, from, to time.Time) error {
	query := fmt.Sprintf("first_seen_at<%s last_seen_at>%s", to.Format(time.RFC3339), from.Format(time.RFC3339))
	campaigns, err := db.SearchCampaigns(0, 100000, query)
	if err != nil {
		return fmt.Errorf("searching campaigns in window: %w", err)
	}

	if len(campaigns) == 0 {
		slog.Info("no campaigns to wipe in window")
		return nil
	}

	slog.Info("wiping campaigns in window",
		slog.Int("count", len(campaigns)),
		slog.Time("from", from),
		slog.Time("to", to),
	)

	for _, c := range campaigns {
		// Clear denormalized campaign_id on requests before deleting the campaign.
		if _, err := db.ParameterizedQuery(
			"UPDATE request SET campaign_id = NULL WHERE campaign_id = $1 AND time_received >= $2 AND time_received <= $3",
			&[]models.Request{}, c.ID, from, to,
		); err != nil {
			slog.Warn("failed to clear request campaign_id",
				slog.Int64("campaign_id", c.ID),
				slog.String("error", err.Error()),
			)
		}

		if err := db.Delete(&c); err != nil {
			return fmt.Errorf("deleting campaign %d: %w", c.ID, err)
		}
		slog.Info("wiped campaign",
			slog.Int64("id", c.ID),
			slog.String("name", c.Name),
			slog.String("status", c.Status),
		)
	}

	slog.Info("wipe complete", slog.Int("campaigns_deleted", len(campaigns)))
	return nil
}
