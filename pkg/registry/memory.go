package registry

import (
	"context"
	"sort"
	"sync"
)

type MemoryRepository struct {
	mu      sync.Mutex
	records map[string]Record
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{records: make(map[string]Record)}
}

func (r *MemoryRepository) Save(_ context.Context, record Record) (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.records[record.Registry]; ok {
		record.CreatedAt = existing.CreatedAt
	}
	r.records[record.Registry] = record
	return record, nil
}

func (r *MemoryRepository) Get(_ context.Context, registry string) (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.records[registry]
	if !ok {
		return Record{}, ErrNotFound
	}
	return record, nil
}

func (r *MemoryRepository) List(_ context.Context) ([]Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	records := make([]Record, 0, len(r.records))
	for _, record := range r.records {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Registry < records[j].Registry
	})
	return records, nil
}
