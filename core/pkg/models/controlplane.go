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
