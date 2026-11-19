package storage

import (
	"context"
	"math/big"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
)

// CRLSettingsRepo only offers scoped writes: a whole-row save would overwrite columns that other writers own
// (status, signer, latest CRL) with a stale copy.
type CRLSettingsRepo interface {
	Insert(ctx context.Context, settings *models.CRLSettings) (*models.CRLSettings, error)
	Get(ctx context.Context, caID string) (bool, *models.CRLSettings, error)
	GetByLegacySKI(ctx context.Context, ski string) (bool, *models.CRLSettings, error)
	GetAll(ctx context.Context, req StorageListRequest[models.CRLSettings]) (string, error)
	// UpdateOptions writes the editable options only.
	UpdateOptions(ctx context.Context, caID string, options models.CRLSettingsOptions) (*models.CRLSettings, error)
	// UpdateLatestCRL writes the latest CRL only, and fails with errs.ErrCRLSettingsConflict if its version is no longer expectedVersion.
	UpdateLatestCRL(ctx context.Context, caID string, expectedVersion *big.Int, latest models.LatestCRLMeta) error
}
