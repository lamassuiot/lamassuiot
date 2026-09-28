package models

import (
	"errors"
	"fmt"
	"time"
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
	Name           string        `json:"name"`
	Status         TenantStatus  `json:"status"`
	IsolationMode  IsolationMode `json:"isolation_mode"`
	CreatedAt      time.Time     `json:"created_at"`
	DeletedAt      *time.Time    `json:"deleted_at,omitempty"`
}

func (tenant Tenant) Validate() error {
	if tenant.ID == "" {
		return errors.New("tenant id is required")
	}
	if tenant.OrganizationID == "" {
		return errors.New("tenant organization is required")
	}
	if tenant.Name == "" {
		return errors.New("tenant name is required")
	}
	if !isTenantStatus(tenant.Status) {
		return fmt.Errorf("unknown tenant status %q", tenant.Status)
	}
	if !isIsolationMode(tenant.IsolationMode) {
		return fmt.Errorf("unknown isolation mode %q", tenant.IsolationMode)
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
		return errors.New("membership id is required")
	}
	if membership.OrganizationID == "" || membership.OrganizationID != organizationID {
		return errors.New("membership organization is invalid")
	}
	if membership.TenantID == "" || membership.TenantID != tenantID {
		return errors.New("membership tenant is invalid")
	}
	if membership.IdentityIssuer == "" || membership.IdentitySubject == "" {
		return errors.New("membership identity issuer and subject are required")
	}
	if !isTenantRole(membership.Role) {
		return fmt.Errorf("unknown tenant role %q", membership.Role)
	}
	if !isMembershipStatus(membership.Status) {
		return fmt.Errorf("unknown membership status %q", membership.Status)
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

// IsTenantRole reports whether role is one of the supported tenant roles.
func IsTenantRole(role TenantRole) bool {
	return isTenantRole(role)
}

// IsIsolationMode reports whether mode is one of the supported isolation modes.
func IsIsolationMode(mode IsolationMode) bool {
	return isIsolationMode(mode)
}

var tenantStatusTransitions = map[TenantStatus][]TenantStatus{
	TenantActive:    {TenantSuspended, TenantDeleted},
	TenantSuspended: {TenantActive, TenantDeleted},
	TenantDeleted:   {TenantRestoring},
	TenantRestoring: {TenantSuspended},
}

// CanTransitionTenantStatus reports whether the tenant lifecycle allows moving from one status to another.
func CanTransitionTenantStatus(from TenantStatus, to TenantStatus) bool {
	for _, allowed := range tenantStatusTransitions[from] {
		if allowed == to {
			return true
		}
	}
	return false
}

type InvitationStatus string

const (
	InvitationPending  InvitationStatus = "PENDING"
	InvitationAccepted InvitationStatus = "ACCEPTED"
	InvitationRevoked  InvitationStatus = "REVOKED"
)

type Invitation struct {
	ID                string           `json:"id" gorm:"primaryKey"`
	OrganizationID    string           `json:"organization_id" gorm:"not null"`
	TenantID          string           `json:"tenant_id" gorm:"index;not null"`
	Role              TenantRole       `json:"role" gorm:"not null"`
	CodeHash          string           `json:"-" gorm:"not null"`
	Status            InvitationStatus `json:"status" gorm:"not null"`
	CreatedByIssuer   string           `json:"created_by_issuer" gorm:"not null"`
	CreatedBySubject  string           `json:"created_by_subject" gorm:"not null"`
	ExpiresAt         time.Time        `json:"expires_at" gorm:"not null"`
	AcceptedByIssuer  *string          `json:"accepted_by_issuer,omitempty"`
	AcceptedBySubject *string          `json:"accepted_by_subject,omitempty"`
	AcceptedAt        *time.Time       `json:"accepted_at,omitempty"`
	CreatedAt         time.Time        `json:"created_at"`
}

// MembershipSummary describes one membership of an identity together with the
// organization and tenant it grants access to.
type MembershipSummary struct {
	MembershipID     string           `json:"membership_id"`
	OrganizationID   string           `json:"organization_id"`
	OrganizationName string           `json:"organization_name"`
	TenantID         string           `json:"tenant_id"`
	TenantName       string           `json:"tenant_name"`
	TenantStatus     TenantStatus     `json:"tenant_status"`
	Role             TenantRole       `json:"role"`
	Status           MembershipStatus `json:"status"`
}

// MembershipUpdate carries the optional changes applied to a membership.
type MembershipUpdate struct {
	Role   *TenantRole
	Status *MembershipStatus
}

// DefaultTenantID is the tenant created by the control plane migration; data
// that existed before multi-tenancy is backfilled into it.
const DefaultTenantID = "00000000-0000-0000-0000-000000000002"
