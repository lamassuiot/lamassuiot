package storage

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
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
	// Delete fails with errs.ErrKeyInUse while resources are bound to the key.
	Delete(ctx context.Context, keyID, engineID string) error
	// DeleteWith deletes the key and runs fn in the same transaction, after the row is deleted: fn only
	// runs for a key no resource is bound to, and an fn error keeps the row.
	DeleteWith(ctx context.Context, keyID, engineID string, fn func() error) error

	// BindResource records that a resource uses the key; created is false if it already did. It fails
	// with errs.ErrKeyNotFound when the key does not exist.
	BindResource(ctx context.Context, keyID, engineID string, resource models.KMSBindResource) (created bool, err error)
	// UnbindResource removes the binding; deleted is false if there was none.
	UnbindResource(ctx context.Context, keyID, engineID string, resource models.KMSBindResource) (deleted bool, err error)
	SelectBindings(ctx context.Context, keyID, engineID string) ([]models.KeyBinding, error)
}
