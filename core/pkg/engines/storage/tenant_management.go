package storage

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

// TenantManagementRepo persists the control plane catalog managed by the
// tenant-manager service. Implementations return errs.ErrTenantManager*
// sentinels for not-found, conflict and lifecycle violations.
type TenantManagementRepo interface {
	CreateOrganization(ctx context.Context, organization *models.Organization) error
	ListOrganizations(ctx context.Context) ([]models.Organization, error)

	// CreateTenantWithAdmin stores the tenant, registers the admin identity if
	// needed and creates its ACTIVE tenant_admin membership atomically.
	CreateTenantWithAdmin(ctx context.Context, tenant *models.Tenant, admin *models.Membership) error
	ListTenants(ctx context.Context, organizationID string) ([]models.Tenant, error)
	UpdateTenantStatus(ctx context.Context, tenantID string, status models.TenantStatus, at time.Time) (*models.Tenant, error)

	ListIdentityMemberships(ctx context.Context, issuer string, subject string) ([]models.MembershipSummary, error)
	ListTenantMemberships(ctx context.Context, tenantID string) ([]models.Membership, error)
	GetTenantMembership(ctx context.Context, tenantID string, membershipID string) (*models.Membership, error)

	// AssignMembership creates the membership, or reactivates a REVOKED one
	// for the same identity and tenant with the requested role.
	AssignMembership(ctx context.Context, membership *models.Membership) (*models.Membership, error)
	// UpdateMembership changes role and/or status while guaranteeing the
	// tenant keeps at least one ACTIVE tenant_admin.
	UpdateMembership(ctx context.Context, tenantID string, membershipID string, update models.MembershipUpdate) (*models.Membership, error)

	CreateInvitation(ctx context.Context, invitation *models.Invitation) error
	ListInvitations(ctx context.Context, tenantID string) ([]models.Invitation, error)
	RevokeInvitation(ctx context.Context, tenantID string, invitationID string) (*models.Invitation, error)
	// AcceptInvitation consumes a PENDING, unexpired invitation for an ACTIVE
	// tenant and grants its role to the given identity.
	AcceptInvitation(ctx context.Context, codeHash string, issuer string, subject string, newMembershipID string, at time.Time) (*models.Membership, error)
}

// TenantManagementStorageProvider is implemented by storage engines that can
// manage the control plane catalog.
type TenantManagementStorageProvider interface {
	GetTenantManagementStorage() (TenantManagementRepo, error)
}
