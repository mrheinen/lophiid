package backend

import (
	"fmt"
	"log/slog"
	"loophid/pkg/database"
	"time"
)

type QueryRunner interface {
	Run(UpdateWindow time.Duration) error
}

type FakeQueryRunner struct {
	ErrorToReturn error
}

func (f *FakeQueryRunner) Run(UpdateWindow time.Duration) error {
	return f.ErrorToReturn
}

type QueryRunnerImpl struct {
	dbc database.DatabaseClient
}

var (
	QueryUpdateWindowWeek = (time.Duration(-168) * time.Hour) // Week
	QueryUpdateWindowHour = (time.Duration(-1) * time.Hour)
)

func NewQueryRunnerImpl(dbc database.DatabaseClient) *QueryRunnerImpl {
	return &QueryRunnerImpl{
		dbc,
	}
}

func (q *QueryRunnerImpl) Run(UpdateWindow time.Duration) error {

	slog.Debug("Running stored queries")
	// Get all queries. Use 1000 as limit for the request;  it's not likely
	// someone will exceed that on short term.
	queries, err := q.dbc.SearchStoredQuery(0, 1000, "")
	if err != nil {
		return fmt.Errorf("fetching queries failed: %w", err)
	}

	if len(queries) == 0 {
		return nil
	}

	timeNow := time.Now()
	timeThen := timeNow.Add(UpdateWindow)

	for _, query := range queries {
		tags, err := q.dbc.SearchTagPerQuery(0, 1000, fmt.Sprintf("query_id:%d", query.ID))
		if err != nil {
			return fmt.Errorf("fetching query tags failed. Query was: %w", err)
		}

		if len(tags) == 0 {
			slog.Debug("query has no tags, skipping it.")
			continue
		}

		// Get the requests for the last month. In the future we might want to
		// change this and apply the tags to requests for a longer period (maybe on
		// all data or on a user provided timeframe).
		searchQuery := fmt.Sprintf("%s created_at>%02d/%02d/%d", query.Query, timeThen.Month(), timeThen.Day(), timeThen.Year())
		slog.Debug("running stored query", slog.String("query", searchQuery))
		reqs, err := q.dbc.SearchRequests(0, 50000, searchQuery)
		if err != nil {
			return fmt.Errorf("fetching requests failed. Query was: '%s' %w", searchQuery, err)
		}

		for _, req := range reqs {
			tagsPerReq, err := q.dbc.GetTagsPerRequestForRequestID(req.ID)
			if err != nil {
				return fmt.Errorf("fetching tags_per_request failed: %w", err)
			}

			for _, t := range tags {
				hasTag := false
				for _, tpr := range tagsPerReq {
					if tpr.RequestID == req.ID && tpr.TagID == t.TagID {
						hasTag = true
						break
					}
				}

				if !hasTag {
					tagToAdd := database.TagPerRequest{
						TagPerQueryID: t.ID,
						RequestID:     req.ID,
						TagID:         t.TagID,
					}
					_, err := q.dbc.Insert(&tagToAdd)

					if err != nil {
						slog.Warn("could not add tag for request", slog.String("error", err.Error()))
					}
				}
			}
		}
	}

	return nil

}
