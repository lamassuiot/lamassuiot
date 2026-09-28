package postgres

import (
	"context"
	"errors"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"gorm.io/gorm"
)

var ErrActiveMembershipNotFound = storage.ErrActiveMembershipNotFound

type ControlPlaneMembershipStore struct {
	db *gorm.DB
}

func NewControlPlaneMembershipRepository(db *gorm.DB) *ControlPlaneMembershipStore {
	return &ControlPlaneMembershipStore{db: db}
}

func (store *ControlPlaneMembershipStore) FindActiveMembership(ctx context.Context, issuer string, subject string, tenantID string) (*models.Membership, *models.Tenant, error) {
	var membership models.Membership
	result := store.db.WithContext(ctx).
		Where("identity_issuer = ? AND identity_subject = ? AND tenant_id = ? AND status = ?", issuer, subject, tenantID, models.MembershipActive).
		First(&membership)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil, ErrActiveMembershipNotFound
	}
	if result.Error != nil {
		return nil, nil, result.Error
	}

	var tenant models.Tenant
	result = store.db.WithContext(ctx).
		Where("id = ? AND status = ? AND deleted_at IS NULL", tenantID, models.TenantActive).
		First(&tenant)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil, ErrActiveMembershipNotFound
	}
	if result.Error != nil {
		return nil, nil, result.Error
	}
	return &membership, &tenant, nil
}

func (store *ControlPlaneMembershipStore) ListActiveTenants(ctx context.Context) ([]models.Tenant, error) {
	var tenants []models.Tenant
	result := store.db.WithContext(ctx).
		Where("status = ? AND deleted_at IS NULL", models.TenantActive).
		Find(&tenants)
	return tenants, result.Error
}

func (store *ControlPlaneMembershipStore) GetActiveTenant(ctx context.Context, tenantID string) (*models.Tenant, error) {
	var tenant models.Tenant
	result := store.db.WithContext(ctx).
		Where("id = ? AND status = ? AND deleted_at IS NULL", tenantID, models.TenantActive).
		First(&tenant)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, ErrActiveMembershipNotFound
	}
	if result.Error != nil {
		return nil, result.Error
	}
	return &tenant, nil
}
