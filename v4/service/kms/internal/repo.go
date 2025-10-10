package internal

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/service/kms"
)

type KMSKeysRepo interface {
	Count(ctx context.Context) (int, error)
	SelectAll(ctx context.Context, req storage.StorageListRequest[kms.Key]) (string, error)
	SelectExistsByID(ctx context.Context, id string) (bool, *kms.Key, error)

	Insert(ctx context.Context, key *kms.Key) (*kms.Key, error)
	Delete(ctx context.Context, id string) error
}
