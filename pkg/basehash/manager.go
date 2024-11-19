package basehash

import (
	"fmt"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util"
)

type BaseHashManager struct {
	cache    *util.StringMapCache[struct{}]
	dbClient database.DatabaseClient
	llmQueue util.Queue[models.BaseHash]
}

// MaybeAddNewHash add the hash to the cache and database if necessary.
func (b *BaseHashManager) MaybeAddNewHash(hash string, req *models.Request) error {
	// First check the cache
	_, err := b.cache.Get(hash)
	if err == nil {
		return nil
	}

	// Next check the database
	res, err := b.dbClient.SearchBaseHash(0, 1, fmt.Sprintf("base_hash:%s", hash))
	if err != nil {
		return fmt.Errorf("failed to check database for base hash %s: %w", hash, err)
	}

	if len(res) == 1 {
		// It's already in the database so update the cache to reflect this.
		b.cache.Store(hash, struct{}{})
		return nil
	}

	// If we get here then we have not seen this hash before so we need to add
	// to the database and additionally put it in the queue for LLM description
	// generation.
	bh := &models.BaseHash{
		BaseHash:         hash,
		ExampleRequestID: req.ID,
	}

	_, err = b.dbClient.Insert(bh)
	if err != nil {
		return fmt.Errorf("failed to insert base hash %s: %w", hash, err)
	}

	b.llmQueue.Push(*bh)
	b.cache.Store(hash, struct{}{})
	return nil
}
