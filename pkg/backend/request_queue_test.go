package backend

import (
	"loophid/pkg/database"
	"testing"
)

func TestRequestQueue(t *testing.T) {
	req := database.Request{}
	q := RequestQueue{}

	if q.Pop() != nil {
		t.Error("Popping an empty queue did not yield nil")
	}

	q.Push(&req)
	if q.Length() != 1 {
		t.Errorf("expected length 1 but got %d", q.Length())
	}

	if q.Pop() != &req {
		t.Error("Queued request is different")
	}
	if q.Length() != 0 {
		t.Errorf("expected length 0 but got %d", q.Length())
	}
}
