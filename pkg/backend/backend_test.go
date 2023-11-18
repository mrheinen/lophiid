package backend

import (
	"context"
	"loophid/backend_service"
	"loophid/pkg/database"
	"testing"
)

func TestHandleProbeOK(t *testing.T) {

	pathToMatch := "/foo/bar"
	fdbc := &database.FakeDatabaseClient{
		ContentToReturn: database.Content{
			Content:     "<b>Hello</b>",
			ContentType: "text/plain; charset=UTF-8",
		},
		ContentRuleToReturn: database.ContentRule{
			Path:         pathToMatch,
			PathMatching: "exact",
		},
	}

	b := NewBackendServer(fdbc)
	if err := b.Start(); err != nil {
		t.Fatalf("loading rules: %s", err)
	}

	req := &backend_service.HandleProbeRequest{
		Request: &backend_service.HttpRequest{
			ParsedUrl: &backend_service.ParsedURL{
				Path: pathToMatch,
			},
		},
	}

	resp, err := b.HandleProbe(context.Background(), req)
	if err != nil {
		t.Errorf("got error : %s", err)
	}
	// Inspect the returned response.
	if resp.Response.Body != fdbc.ContentToReturn.Content {
		t.Errorf("expected %s, got %s", fdbc.ContentToReturn.Content, resp.Response.Body)
	}
}
