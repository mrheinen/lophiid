package util

import "sync"

// A simple threadsafe queue implementation
type Queue[T any] struct {
	items []T
	mu    sync.RWMutex
}

func (q *Queue[T]) Pop() *T {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.items) == 0 {
		return nil
	}

	ret := q.items[0]
	q.items = q.items[1:]
	return &ret
}

func (q *Queue[T]) Push(item T) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.items = append(q.items, item)
}

func (q *Queue[T]) Len() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.items)
}
