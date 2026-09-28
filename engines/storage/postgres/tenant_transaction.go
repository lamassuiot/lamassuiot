package postgres

import (
	"context"
	"errors"

	core "github.com/lamassuiot/lamassuiot/core/v3"
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

	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT set_config('app.tenant_id', ?, true)", tenantContext.TenantID).Error; err != nil {
			return err
		}
		return operation(tx)
	})
}
