package storage

import (
	"context"
	"errors"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

// ErrActiveMembershipNotFound means the identity has no ACTIVE membership in
// an ACTIVE tenant. Any other error from the repository is an infrastructure
// failure and must not be reported as an authorization denial.
var ErrActiveMembershipNotFound = errors.New("active tenant membership not found")

type ControlPlaneMembershipRepo interface {
	FindActiveMembership(ctx context.Context, issuer string, subject string, tenantID string) (*models.Membership, *models.Tenant, error)
}

// ActiveTenantLister is an optional worker-facing capability. It is kept
// separate from ControlPlaneMembershipRepo so HTTP identity stubs do not need
// to implement tenant enumeration.
type ActiveTenantLister interface {
	ListActiveTenants(ctx context.Context) ([]models.Tenant, error)
}

// NonDeletedTenantLister enumerates every tenant that has not been deleted,
// whatever its status, for startup maintenance steps such as the KMS key
// migration to tenant roots (004 T4.6).
type NonDeletedTenantLister interface {
	ListNonDeletedTenants(ctx context.Context) ([]models.Tenant, error)
}

// ActiveTenantGetter resolves one ACTIVE, non-deleted tenant by ID. Public PKI
// endpoints use it to build a tenant context from the tenant in the URL.
type ActiveTenantGetter interface {
	GetActiveTenant(ctx context.Context, tenantID string) (*models.Tenant, error)
}
