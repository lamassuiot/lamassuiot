package postgres

import (
	"context"
	"errors"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"gorm.io/gorm"
)

type ControlPlaneTenantStore struct {
	db *gorm.DB
}

func NewControlPlaneTenantRepository(db *gorm.DB) *ControlPlaneTenantStore {
	return &ControlPlaneTenantStore{db: db}
}

func (store *ControlPlaneTenantStore) ListActiveTenants(ctx context.Context) ([]models.Tenant, error) {
	var tenants []models.Tenant
	result := store.db.WithContext(ctx).
		Where("status = ? AND deleted_at IS NULL", models.TenantActive).
		Find(&tenants)
	return tenants, result.Error
}

func (store *ControlPlaneTenantStore) GetActiveTenant(ctx context.Context, tenantID string) (*models.Tenant, error) {
	var tenant models.Tenant
	result := store.db.WithContext(ctx).
		Where("id = ? AND status = ? AND deleted_at IS NULL", tenantID, models.TenantActive).
		First(&tenant)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, errs.ErrTenantNotFound
	}
	if result.Error != nil {
		return nil, result.Error
	}
	return &tenant, nil
}
