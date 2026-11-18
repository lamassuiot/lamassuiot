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
	// Delete fails with errs.ErrKeyInUse while a certificate references the key.
	Delete(ctx context.Context, keyID, engineID string) error
	// DeleteWith deletes the key and runs fn in the same transaction, after the row is deleted: fn does
	// not run for a key a certificate references, and an fn error keeps the row. If the commit fails
	// after fn ran, the row stays without the engine copy fn deleted.
	DeleteWith(ctx context.Context, keyID, engineID string, fn func() error) error
	// RenameKey changes the key_id of a key in one engine, keeping the old one as an alias; the
	// certificates that reference the key follow it. renameInEngine renames the engine copy; the key only
	// changes if it succeeds. renamed is false, and renameInEngine is not run, if no key has the old key_id.
	RenameKey(ctx context.Context, engineID, oldKeyID, newKeyID string, renameInEngine func() error) (renamed bool, err error)
}
