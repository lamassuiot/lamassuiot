package postgres

import (
	"context"
	"errors"

	"github.com/lamassuiot/lamassuiot/v4/core"
	"gorm.io/gorm"
)

func WithTenantTransaction(ctx context.Context, db *gorm.DB, operation func(*gorm.DB) error) error {
	if db == nil {
		return errors.New("tenant transaction database is required")
	}
	if operation == nil {
		return errors.New("tenant transaction operation is required")
	}

	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return err
	}

	return withTenantIDTransaction(ctx, db, tenantContext.TenantID, operation)
}

func withTenantIDTransaction(ctx context.Context, db *gorm.DB, tenantID string, operation func(*gorm.DB) error) error {
	if tenantID == "" {
		return errors.New("tenant transaction tenant id is required")
	}

	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT set_config('app.tenant_id', ?, true)", tenantID).Error; err != nil {
			return err
		}
		return operation(tx)
	})
}
