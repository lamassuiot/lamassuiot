package postgres

import (
	"context"
	"errors"
	"fmt"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrDedicatedCryptoSelectorNotFound = errors.New("dedicated crypto selector not found")
var ErrDedicatedCryptoSelectorChanged = errors.New("dedicated crypto selector changed")

type DedicatedCryptoSelectorStore struct {
	db *gorm.DB
}

func NewDedicatedCryptoSelectorRepository(db *gorm.DB) *DedicatedCryptoSelectorStore {
	return &DedicatedCryptoSelectorStore{db: db}
}

func (store *DedicatedCryptoSelectorStore) Initialize(ctx context.Context, selector models.DedicatedCryptoSelector) error {
	tenant, err := core.RequireTenantContext(ctx)
	if err != nil {
		return err
	}
	if selector.TenantID != tenant.TenantID || selector.CAID == "" || selector.EngineID == "" || selector.KeyID == "" {
		return core.ErrTenantResourceAccessDenied
	}
	selector.Version = 1
	result := store.db.WithContext(ctx).Where("tenant_id = ?", tenant.TenantID).Attrs(selector).FirstOrCreate(&models.DedicatedCryptoSelector{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return storage.ErrDedicatedCryptoSelectorAlreadyInitialized
	}
	return nil
}

func (store *DedicatedCryptoSelectorStore) Select(ctx context.Context) (*models.DedicatedCryptoSelector, error) {
	tenant, err := core.RequireTenantContext(ctx)
	if err != nil {
		return nil, err
	}
	var selector models.DedicatedCryptoSelector
	result := store.db.WithContext(ctx).Where("tenant_id = ?", tenant.TenantID).First(&selector)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, ErrDedicatedCryptoSelectorNotFound
	}
	if result.Error != nil {
		return nil, result.Error
	}
	return &selector, nil
}

func (store *DedicatedCryptoSelectorStore) Switch(ctx context.Context, expectedCAID string, candidate models.DedicatedCryptoSelector) error {
	tenant, err := core.RequireTenantContext(ctx)
	if err != nil {
		return err
	}
	if candidate.TenantID != tenant.TenantID || candidate.CAID == "" || candidate.EngineID == "" || candidate.KeyID == "" {
		return core.ErrTenantResourceAccessDenied
	}

	return store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current models.DedicatedCryptoSelector
		result := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("tenant_id = ?", tenant.TenantID).First(&current)
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return ErrDedicatedCryptoSelectorNotFound
		}
		if result.Error != nil {
			return result.Error
		}
		if current.CAID != expectedCAID {
			return fmt.Errorf("%w: expected CA %q, found %q", ErrDedicatedCryptoSelectorChanged, expectedCAID, current.CAID)
		}
		candidate.Version = current.Version + 1
		return tx.Model(&current).Updates(map[string]any{
			"ca_id":      candidate.CAID,
			"engine_id":  candidate.EngineID,
			"key_id":     candidate.KeyID,
			"version":    candidate.Version,
			"updated_at": candidate.UpdatedAt,
		}).Error
	})
}

func (store *DedicatedCryptoSelectorStore) Restore(ctx context.Context, selector models.DedicatedCryptoSelector) error {
	tenant, err := core.RequireTenantContext(ctx)
	if err != nil {
		return err
	}
	if selector.TenantID != tenant.TenantID {
		return core.ErrTenantResourceAccessDenied
	}
	if selector.CAID == "" || selector.EngineID == "" || selector.KeyID == "" {
		return errors.New("selector to restore is incomplete")
	}
	return store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current models.DedicatedCryptoSelector
		result := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("tenant_id = ?", tenant.TenantID).First(&current)
		if result.Error != nil {
			return result.Error
		}
		if current.Version < selector.Version {
			return ErrDedicatedCryptoSelectorChanged
		}
		selector.Version = current.Version + 1
		return tx.Model(&current).Updates(map[string]any{
			"ca_id":      selector.CAID,
			"engine_id":  selector.EngineID,
			"key_id":     selector.KeyID,
			"version":    selector.Version,
			"updated_at": selector.UpdatedAt,
		}).Error
	})
}
