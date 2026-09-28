package models

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTenantValidate(t *testing.T) {
	validTenant := Tenant{
		ID:             "tenant-1",
		OrganizationID: "org-1",
		Name:           "Factory North",
		Status:         TenantActive,
		IsolationMode:  IsolationPooled,
	}

	require.NoError(t, validTenant.Validate())

	invalidTenant := validTenant
	invalidTenant.OrganizationID = ""
	require.Error(t, invalidTenant.Validate())

	invalidStatus := validTenant
	invalidStatus.Status = TenantStatus("UNKNOWN")
	require.Error(t, invalidStatus.Validate())
}

func TestMembershipValidate(t *testing.T) {
	validMembership := Membership{
		ID:              "membership-1",
		OrganizationID:  "org-1",
		TenantID:        "tenant-1",
		IdentityIssuer:  "https://issuer.example",
		IdentitySubject: "subject-1",
		Role:            RoleTenantAdmin,
		Status:          MembershipActive,
	}

	require.NoError(t, validMembership.Validate("org-1", "tenant-1"))

	invalidIdentity := validMembership
	invalidIdentity.IdentitySubject = ""
	require.Error(t, invalidIdentity.Validate("org-1", "tenant-1"))

	crossTenant := validMembership
	require.Error(t, crossTenant.Validate("org-1", "tenant-2"))
}

func TestCanTransitionTenantStatus(t *testing.T) {
	allowed := [][2]TenantStatus{
		{TenantActive, TenantSuspended},
		{TenantSuspended, TenantActive},
		{TenantActive, TenantDeprovisioning},
		{TenantSuspended, TenantDeprovisioning},
		{TenantDeprovisioning, TenantDeleted},
		{TenantDeleted, TenantRestoring},
		{TenantRestoring, TenantSuspended},
	}
	for _, transition := range allowed {
		require.True(t, CanTransitionTenantStatus(transition[0], transition[1]), "%s -> %s", transition[0], transition[1])
	}

	denied := [][2]TenantStatus{
		{TenantActive, TenantDeleted},
		{TenantDeleted, TenantActive},
		{TenantRestoring, TenantActive},
		{TenantProvisioning, TenantActive},
		{TenantActive, TenantActive},
	}
	for _, transition := range denied {
		require.False(t, CanTransitionTenantStatus(transition[0], transition[1]), "%s -> %s", transition[0], transition[1])
	}
}
