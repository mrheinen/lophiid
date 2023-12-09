package backend

import (
	"context"
	"fmt"
	"loophid/backend_service"
	"loophid/pkg/database"
	"testing"
)

func TestHandleProbeMatchesSingleRuleOK(t *testing.T) {

	originalPath := "/foo/bar"
	expectedContentId := int64(42)
	fdbc := &database.FakeDatabaseClient{
		ContentsToReturn: map[int64]database.Content{
			expectedContentId: database.Content{
				Content:     "<b>Hello</b>",
				ContentType: "text/plain; charset=UTF-8",
				ID:          expectedContentId,
			},
			55: database.Content{
				Content:     "<b>NO</b>",
				ContentType: "text/html; charset=UTF-8",
				ID:          55,
			},
		},
		ContentRulesToReturn: []database.ContentRule{{
			ID:           1,
			Port:         0,
			Path:         originalPath,
			PathMatching: "exact",
			ContentID:    expectedContentId,
		},
		},
	}

	b := NewBackendServer(fdbc)
	if err := b.Start(); err != nil {
		t.Fatalf("loading rules: %s", err)
	}

	for _, test := range []struct {
		description        string
		contentShouldMatch bool
		pathToMatch        string
	}{
		{
			description:        "should match",
			contentShouldMatch: true,
			pathToMatch:        originalPath,
		},
		{
			description:        "content should be different",
			contentShouldMatch: false,
			pathToMatch:        "/shouldnotmatch",
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			req := &backend_service.HandleProbeRequest{
				Request: &backend_service.HttpRequest{
					RemoteAddress: "127.0.0.1:4444",
					ParsedUrl: &backend_service.ParsedURL{
						Path: test.pathToMatch,
					},
				},
			}
			resp, err := b.HandleProbe(context.Background(), req)
			if err != nil {
				t.Errorf("got error : %s", err)
			}

			// Inspect the returned response.
			if (resp.Response.Body == fdbc.ContentsToReturn[expectedContentId].Content) != test.contentShouldMatch {
				t.Errorf("expected %s, got %s", fdbc.ContentsToReturn[expectedContentId].Content, resp.Response.Body)
			}

		})
	}
	b.Stop()
}

func TestHandleProbeMatchesMultipleRuleOK(t *testing.T) {

	originalPath := "/foo/bar"
	for _, test := range []struct {
		description        string
		contentShouldMatch bool
		pathToMatch        string
		portToMatch        int64
		contentRules       []database.ContentRule
		expectedContentIds []int64
		contentsToReturn   map[int64]database.Content
		uniqueKeysToReturn map[string][]string
	}{
		{
			description:        "two rules with same path but one matches port",
			contentShouldMatch: true,
			pathToMatch:        originalPath,
			portToMatch:        8080,
			contentRules: []database.ContentRule{
				{ID: 1, Port: 80, Path: originalPath, PathMatching: "exact", ContentID: 42},
				{ID: 2, Port: 8080, Path: originalPath, PathMatching: "exact", ContentID: 55},
			},
			expectedContentIds: []int64{55},
			contentsToReturn: map[int64]database.Content{
				42: database.Content{
					Content:     "<b>Hello</b>",
					ContentType: "text/plain; charset=UTF-8",
					ID:          42,
				},
				55: database.Content{
					Content:     "<b>NO</b>",
					ContentType: "text/html; charset=UTF-8",
					ID:          55,
				},
			},
			uniqueKeysToReturn: map[string][]string{},
		},
		{
			description:        "two rules, one matches exact",
			contentShouldMatch: true,
			pathToMatch:        originalPath,
			portToMatch:        80,
			contentRules: []database.ContentRule{
				{ID: 1, Port: 80, Path: originalPath, PathMatching: "exact", ContentID: 42},
				{ID: 2, Port: 80, Path: "/someotherpath", PathMatching: "exact", ContentID: 55},
			},
			expectedContentIds: []int64{42},
			contentsToReturn: map[int64]database.Content{
				42: database.Content{
					Content:     "<b>Hello</b>",
					ContentType: "text/plain; charset=UTF-8",
					ID:          42,
				},
				55: database.Content{
					Content:     "<b>NO</b>",
					ContentType: "text/html; charset=UTF-8",
					ID:          55,
				},
			},
			uniqueKeysToReturn: map[string][]string{},
		},
		{
			description:        "two rules, one matches prefix",
			contentShouldMatch: true,
			pathToMatch:        originalPath,
			portToMatch:        80,
			contentRules: []database.ContentRule{
				{ID: 1, Port: 80, Path: originalPath, PathMatching: "prefix", ContentID: 42},
				{ID: 2, Port: 80, Path: "/someotherpath", PathMatching: "exact", ContentID: 55},
			},
			expectedContentIds: []int64{42},
			contentsToReturn: map[int64]database.Content{
				42: database.Content{
					Content:     "<b>Hello</b>",
					ContentType: "text/plain; charset=UTF-8",
					ID:          42,
				},
				55: database.Content{
					Content:     "<b>NO</b>",
					ContentType: "text/html; charset=UTF-8",
					ID:          55,
				},
			},
			uniqueKeysToReturn: map[string][]string{},
		},
		{
			description:        "two rules, one matches contains",
			contentShouldMatch: true,
			pathToMatch:        originalPath,
			portToMatch:        80,
			contentRules: []database.ContentRule{
				{ID: 1, Port: 80, Path: "/ba", PathMatching: "contains", ContentID: 42},
				{ID: 2, Port: 80, Path: "/someotherpath", PathMatching: "exact", ContentID: 43},
			},
			expectedContentIds: []int64{42},
			contentsToReturn: map[int64]database.Content{
				42: database.Content{
					Content:     "<b>Hello</b>",
					ContentType: "text/plain; charset=UTF-8",
					ID:          42,
				},
				43: database.Content{
					Content:     "<b>NO</b>",
					ContentType: "text/html; charset=UTF-8",
					ID:          43,
				},
			},
			uniqueKeysToReturn: map[string][]string{},
		},
		{
			description:        "two rules, one matches suffix",
			contentShouldMatch: true,
			pathToMatch:        originalPath,
			portToMatch:        80,
			contentRules: []database.ContentRule{
				{ID: 1, Port: 80, Path: "/someotherpath", PathMatching: "exact", ContentID: 42},
				{ID: 2, Port: 80, Path: "bar", PathMatching: "suffix", ContentID: 43},
			},
			expectedContentIds: []int64{43},
			contentsToReturn: map[int64]database.Content{
				42: database.Content{
					Content:     "<b>Hello</b>",
					ContentType: "text/plain; charset=UTF-8",
					ID:          42,
				},
				43: database.Content{
					Content:     "<b>NO</b>",
					ContentType: "text/html; charset=UTF-8",
					ID:          43,
				},
			},
			uniqueKeysToReturn: map[string][]string{},
		},

		{
			description:        "two rules, both match, different contents",
			contentShouldMatch: true,
			pathToMatch:        originalPath,
			portToMatch:        80,
			// Both rules match the same path
			contentRules: []database.ContentRule{
				{ID: 1, Port: 80, Path: originalPath, PathMatching: "exact", ContentID: 42},
				{ID: 2, Port: 80, Path: originalPath, PathMatching: "exact", ContentID: 55},
			},
			// We only expect the second though whereas normally the first is shared.
			// We repeat the ID multiple times to make sure the result us getting
			// lucky.
			expectedContentIds: []int64{55, 55, 55},
			contentsToReturn: map[int64]database.Content{
				42: database.Content{
					Content:     "<b>Hello</b>",
					ContentType: "text/plain; charset=UTF-8",
					ID:          42,
				},
				55: database.Content{
					Content:     "<b>NO</b>",
					ContentType: "text/html; charset=UTF-8",
					ID:          55,
				},
			},
			// The backend will be told that the first was already served.
			uniqueKeysToReturn: map[string][]string{
				"127.0.0.1": []string{"1-42"},
			},
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			fmt.Printf("Running: %s\n", test.description)
			fdbc := &database.FakeDatabaseClient{
				ContentsToReturn:           test.contentsToReturn,
				ContentRulesToReturn:       test.contentRules,
				UniqueKeyPerSourceToReturn: test.uniqueKeysToReturn,
			}

			b := NewBackendServer(fdbc)
			if err := b.Start(); err != nil {
				t.Fatalf("loading rules: %s", err)
			}

			req := &backend_service.HandleProbeRequest{
				Request: &backend_service.HttpRequest{
					RemoteAddress: "127.0.0.1:3117",
					ParsedUrl: &backend_service.ParsedURL{
						Path: test.pathToMatch,
						Port: test.portToMatch,
					},
				},
			}

			for _, id := range test.expectedContentIds {
				resp, err := b.HandleProbe(context.Background(), req)
				if err != nil {
					t.Errorf("got error : %s", err)
				}

				// Inspect the returned response.
				content := test.contentsToReturn[id].Content
				if (resp.Response.Body == content) != test.contentShouldMatch {
					t.Errorf("expected %s, got %s", content, resp.Response.Body)
				}
			}
			b.Stop()
		})
	}
}
