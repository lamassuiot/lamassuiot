package storage

import (
	"context"
	"errors"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
)

var ErrActiveMembershipNotFound = errors.New("active tenant membership not found")

type ControlPlaneMembershipRepo interface {
	FindActiveMembership(ctx context.Context, issuer string, subject string, tenantID string) (*models.Membership, *models.Tenant, error)
}

type ActiveTenantLister interface {
	ListActiveTenants(ctx context.Context) ([]models.Tenant, error)
}

type ActiveTenantGetter interface {
	GetActiveTenant(ctx context.Context, tenantID string) (*models.Tenant, error)
}
