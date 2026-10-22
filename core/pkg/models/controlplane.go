package models

import (
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
)

const (
	DefaultOrganizationID = "00000000-0000-0000-0000-000000000001"
	DefaultTenantID       = "00000000-0000-0000-0000-000000000002"
)

type IsolationMode string

const (
	IsolationPooled            IsolationMode = "POOLED"
	IsolationDedicatedDatabase IsolationMode = "DEDICATED_DATABASE"
	IsolationDedicatedCrypto   IsolationMode = "DEDICATED_CRYPTO"
	IsolationFullyDedicated    IsolationMode = "FULLY_DEDICATED"
)

type TenantStatus string

const (
	TenantActive    TenantStatus = "ACTIVE"
	TenantSuspended TenantStatus = "SUSPENDED"
	TenantDeleted   TenantStatus = "DELETED"
	TenantRestoring TenantStatus = "RESTORING"
)

type MembershipStatus string

const (
	MembershipActive    MembershipStatus = "ACTIVE"
	MembershipSuspended MembershipStatus = "SUSPENDED"
	MembershipRevoked   MembershipStatus = "REVOKED"
)

type TenantRole string

const (
	RoleTenantAdmin TenantRole = "tenant_admin"
	RolePKIAdmin    TenantRole = "pki_admin"
	RoleOperator    TenantRole = "operator"
	RoleEnroller    TenantRole = "enroller"
	RoleAuditor     TenantRole = "auditor"
	RoleViewer      TenantRole = "viewer"
)

type Organization struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type Tenant struct {
	ID             string        `json:"id" gorm:"primaryKey"`
	OrganizationID string        `json:"organization_id" gorm:"index;not null"`
	InstallationID string        `json:"installation_id" gorm:"not null"`
	Name           string        `json:"name"`
	Status         TenantStatus  `json:"status"`
	IsolationMode  IsolationMode `json:"isolation_mode"`
	CreatedAt      time.Time     `json:"created_at"`
	DeletedAt      *time.Time    `json:"deleted_at,omitempty"`
}

func (tenant Tenant) Validate() error {
	if tenant.ID == "" {
		return fmt.Errorf("%w: tenant id is required", errs.ErrInvalidTenant)
	}
	if tenant.OrganizationID == "" {
		return fmt.Errorf("%w: tenant organization is required", errs.ErrInvalidTenant)
	}
	if tenant.InstallationID == "" {
		return fmt.Errorf("%w: tenant installation is required", errs.ErrInvalidTenant)
	}
	if tenant.Name == "" {
		return fmt.Errorf("%w: tenant name is required", errs.ErrInvalidTenant)
	}
	if !isTenantStatus(tenant.Status) {
		return fmt.Errorf("%w: unknown tenant status %q", errs.ErrInvalidTenant, tenant.Status)
	}
	if !isIsolationMode(tenant.IsolationMode) {
		return fmt.Errorf("%w: unknown isolation mode %q", errs.ErrInvalidTenant, tenant.IsolationMode)
	}
	return nil
}

type Identity struct {
	Issuer    string    `json:"issuer" gorm:"primaryKey"`
	Subject   string    `json:"subject" gorm:"primaryKey"`
	CreatedAt time.Time `json:"created_at"`
}

type Membership struct {
	ID              string           `json:"id" gorm:"primaryKey"`
	OrganizationID  string           `json:"organization_id" gorm:"index;not null"`
	TenantID        string           `json:"tenant_id" gorm:"index;not null"`
	IdentityIssuer  string           `json:"identity_issuer" gorm:"index;not null"`
	IdentitySubject string           `json:"identity_subject" gorm:"index;not null"`
	Role            TenantRole       `json:"role"`
	Status          MembershipStatus `json:"status"`
	CreatedAt       time.Time        `json:"created_at"`
}

func (membership Membership) Validate(organizationID string, tenantID string) error {
	if membership.ID == "" {
		return fmt.Errorf("%w: membership id is required", errs.ErrInvalidMembership)
	}
	if membership.OrganizationID == "" || membership.OrganizationID != organizationID {
		return fmt.Errorf("%w: membership organization is invalid", errs.ErrInvalidMembership)
	}
	if membership.TenantID == "" || membership.TenantID != tenantID {
		return fmt.Errorf("%w: membership tenant is invalid", errs.ErrInvalidMembership)
	}
	if membership.IdentityIssuer == "" || membership.IdentitySubject == "" {
		return fmt.Errorf("%w: membership identity issuer and subject are required", errs.ErrInvalidMembership)
	}
	if !isTenantRole(membership.Role) {
		return fmt.Errorf("%w: unknown tenant role %q", errs.ErrInvalidMembership, membership.Role)
	}
	if !isMembershipStatus(membership.Status) {
		return fmt.Errorf("%w: unknown membership status %q", errs.ErrInvalidMembership, membership.Status)
	}
	return nil
}

func isTenantStatus(status TenantStatus) bool {
	switch status {
	case TenantActive, TenantSuspended, TenantDeleted, TenantRestoring:
		return true
	default:
		return false
	}
}

func isIsolationMode(mode IsolationMode) bool {
	switch mode {
	case IsolationPooled, IsolationDedicatedDatabase, IsolationDedicatedCrypto, IsolationFullyDedicated:
		return true
	default:
		return false
	}
}

func isMembershipStatus(status MembershipStatus) bool {
	switch status {
	case MembershipActive, MembershipSuspended, MembershipRevoked:
		return true
	default:
		return false
	}
}

func isTenantRole(role TenantRole) bool {
	switch role {
	case RoleTenantAdmin, RolePKIAdmin, RoleOperator, RoleEnroller, RoleAuditor, RoleViewer:
		return true
	default:
		return false
	}
}

func IsTenantRole(role TenantRole) bool {
	return isTenantRole(role)
}

func IsIsolationMode(mode IsolationMode) bool {
	return isIsolationMode(mode)
}

var tenantStatusTransitions = map[TenantStatus][]TenantStatus{
	TenantActive:    {TenantSuspended, TenantDeleted},
	TenantSuspended: {TenantActive, TenantDeleted},
	TenantDeleted:   {TenantRestoring},
	TenantRestoring: {TenantSuspended},
}

func CanTransitionTenantStatus(from TenantStatus, to TenantStatus) bool {
	for _, allowed := range tenantStatusTransitions[from] {
		if allowed == to {
			return true
		}
	}
	return false
}
