// Lophiid distributed honeypot
// Copyright (C) 2024 Niels Heinen
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
package describer

import (
	"fmt"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"time"
)

type DescriberClient interface {
	MaybeAddNewHash(hash string, req *models.Request) error
}

type CachedDescriberClient struct {
	dbClient database.DatabaseClient
	cache    *util.StringMapCache[struct{}]
}

type FakeDescriberClient struct {
	ErrorToReturn error
}

func (f *FakeDescriberClient) MaybeAddNewHash(hash string, req *models.Request) error {
	return f.ErrorToReturn
}

// GetNewCachedDescriberClient returns a new CachedDescriberClient
func GetNewCachedDescriberClient(dbClient database.DatabaseClient, cacheTimeout time.Duration) *CachedDescriberClient {
	cache := util.NewStringMapCache[struct{}]("CmpHash cache", cacheTimeout)
	cache.Start()

	return &CachedDescriberClient{
		dbClient: dbClient,
		cache:    cache,
	}
}

// MaybeAddNewHash add the hash to the cache and database if necessary. If a
// hash is added to the database then it will be scheduled for describing by an
// LLM.
func (b *CachedDescriberClient) MaybeAddNewHash(hash string, req *models.Request) error {
	// First check the cache
	_, err := b.cache.Get(hash)
	if err == nil {
		return nil
	}

	// Next check the database
	res, err := b.dbClient.SearchRequestDescription(0, 1, fmt.Sprintf("cmp_hash:%s", hash))
	if err != nil {
		return fmt.Errorf("failed to check database for request description %s: %w", hash, err)
	}

	if len(res) == 1 {
		// It's already in the database so update the cache to reflect this.
		b.cache.Store(hash, struct{}{})
		return nil
	}

	// If we get here then we have not seen this hash before so we need to add
	// to the database and additionally put it in the queue for LLM description
	// generation.
	bh := &models.RequestDescription{
		CmpHash:          hash,
		ExampleRequestID: req.ID,
		ReviewStatus:     constants.DescriberUnreviewed,
		TriageStatus:     constants.TriageStatusTypePending,
	}

	_, err = b.dbClient.Insert(bh)
	if err != nil {
		return fmt.Errorf("failed to insert description: %s: %w", hash, err)
	}

	b.cache.Store(hash, struct{}{})
	return nil
}
