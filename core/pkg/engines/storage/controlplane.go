package storage

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
)

type ControlPlaneTenantRepo interface {
	ListActiveTenants(ctx context.Context) ([]models.Tenant, error)
	GetActiveTenant(ctx context.Context, tenantID string) (*models.Tenant, error)
}
