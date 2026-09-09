package storage

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

type KMSKeysRepo interface {
	Count(ctx context.Context) (int, error)
	CountWithFilters(ctx context.Context, queryParams *resources.QueryParameters) (int, error)
	CountByEngineWithFilters(ctx context.Context, engineID string, queryParams *resources.QueryParameters) (int, error)
	SelectAll(ctx context.Context, req StorageListRequest[models.Key]) (string, error)
	// SelectExistsByKeyID looks a key up by its full identity. The same keyID can live in
	// several engines at once (e.g. the private key in an offline HSM and the public key in
	// an online engine), so engineID is required to address a single row.
	SelectExistsByKeyID(ctx context.Context, keyID, engineID string) (bool, *models.Key, error)
	SelectExistsByAlias(ctx context.Context, alias string) (bool, *models.Key, error)
	// SelectByKeyID returns every engine's copy of the given keyID. A keyID alone is a
	// search, not an identity: it resolves a key only while a single engine holds it.
	SelectByKeyID(ctx context.Context, keyID string) ([]*models.Key, error)

	Insert(ctx context.Context, key *models.Key) (*models.Key, error)
	Update(ctx context.Context, key *models.Key) (*models.Key, error)
	Delete(ctx context.Context, keyID, engineID string) error
}
