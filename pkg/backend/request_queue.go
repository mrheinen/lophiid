package backend

import (
	"loophid/pkg/database"
	"sync"
)

type RequestQueue struct {
	mu   sync.Mutex
	reqs []*database.Request
}

func (r *RequestQueue) Pop() *database.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.reqs) == 0 {
		return nil
	}

	ret := r.reqs[0]
	r.reqs = r.reqs[1:]
	return ret
}

func (r *RequestQueue) Length() int {
	return len(r.reqs)
}

func (r *RequestQueue) Push(req *database.Request) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	r.mu.Unlock()
}
