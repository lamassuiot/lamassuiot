package storage

import (
	"context"
	"errors"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

var ErrDedicatedCryptoSelectorAlreadyInitialized = errors.New("dedicated crypto selector already initialized")

// DedicatedCryptoSelectorRepo stores the active CA/key/engine tuple per tenant.
// Switch must be atomic and must leave the current selector unchanged on error.
type DedicatedCryptoSelectorRepo interface {
	Initialize(ctx context.Context, selector models.DedicatedCryptoSelector) error
	Select(ctx context.Context) (*models.DedicatedCryptoSelector, error)
	Switch(ctx context.Context, expectedCAID string, candidate models.DedicatedCryptoSelector) error
	Restore(ctx context.Context, selector models.DedicatedCryptoSelector) error
}
