package core

import (
	"context"
	"errors"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"

	"github.com/stretchr/testify/require"
)

func TestTenantContextValidation(t *testing.T) {
	tests := []struct {
		name    string
		context TenantContext
		wantErr bool
	}{
		{
			name: "valid context",
			context: TenantContext{
				OrganizationID: "org-1",
				TenantID:       "tenant-1",
				ActorID:        "issuer-a:subject-1",
				ActorType:      "user",
				Permissions:    []string{"certificates.read"},
				CorrelationID:  "corr-1",
				Source:         "oidc-membership",
				Validated:      true,
			},
		},
		{
			name:    "missing tenant",
			context: TenantContext{OrganizationID: "org-1", ActorID: "actor-1", Validated: true},
			wantErr: true,
		},
		{
			name:    "unvalidated context",
			context: TenantContext{OrganizationID: "org-1", TenantID: "tenant-1", ActorID: "actor-1"},
			wantErr: true,
		},
		{
			name:    "suspended tenant",
			context: TenantContext{OrganizationID: "org-1", TenantID: "tenant-1", ActorID: "actor-1", Validated: true, TenantStatus: TenantSuspended},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.context.Validate()
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestNewValidatedTenantContextRequiresActiveMatchingMembership(t *testing.T) {
	tenant := models.Tenant{
		ID:             "tenant-1",
		OrganizationID: "org-1",
		Status:         models.TenantActive,
	}
	membership := models.Membership{
		TenantID:       "tenant-1",
		OrganizationID: "org-1",
		Role:           models.RolePKIAdmin,
		Status:         models.MembershipActive,
	}

	tenantContext, err := NewValidatedTenantContext(membership, tenant, "actor-1", "jwt", []string{"read"}, "corr-1", "oidc")
	if err != nil {
		t.Fatalf("expected valid tenant context, got %v", err)
	}
	if err := tenantContext.Validate(); err != nil {
		t.Fatalf("expected validated tenant context, got %v", err)
	}
	if tenantContext.EffectiveRole != models.RolePKIAdmin {
		t.Fatalf("expected effective role from active membership, got %q", tenantContext.EffectiveRole)
	}

	membership.Status = models.MembershipSuspended
	if _, err := NewValidatedTenantContext(membership, tenant, "actor-1", "jwt", nil, "corr-1", "oidc"); err == nil {
		t.Fatal("expected suspended membership to be rejected")
	}

	otherTenantMembership := membership
	otherTenantMembership.Status = models.MembershipActive
	otherTenantMembership.TenantID = "tenant-2"
	if _, err := NewValidatedTenantContext(otherTenantMembership, tenant, "actor-1", "jwt", nil, "corr-1", "oidc"); !errors.Is(err, ErrTenantResourceAccessDenied) {
		t.Fatalf("expected membership of another tenant to be rejected, got %v", err)
	}
}

func TestCanonicalActorIDIncludesIssuerAndSubject(t *testing.T) {
	first := CanonicalActorID("https://issuer-a", "same-subject")
	second := CanonicalActorID("https://issuer-b", "same-subject")
	if first == second || CanonicalActorID("https://issuer-a", "subject-a") == CanonicalActorID("https://issuer-a", "subject-b") {
		t.Fatal("canonical actor identity must retain both issuer and subject")
	}
}

func TestTenantContextRoundTrip(t *testing.T) {
	tenantContext := TenantContext{
		OrganizationID: "org-1",
		TenantID:       "tenant-1",
		ActorID:        "actor-1",
		ActorType:      "service",
		Permissions:    []string{"devices.read"},
		CorrelationID:  "corr-1",
		Source:         "service-token",
		Validated:      true,
	}

	ctx := WithTenantContext(context.Background(), tenantContext)
	got, err := TenantContextFromContext(ctx)

	require.NoError(t, err)
	require.Equal(t, tenantContext, got)
}

func TestRequireTenantContext(t *testing.T) {
	tenantContext := TenantContext{
		OrganizationID: "org-1",
		TenantID:       "tenant-1",
		ActorID:        "actor-1",
		ActorType:      "service",
		CorrelationID:  "corr-1",
		Source:         "service-token",
		Validated:      true,
	}

	got, err := RequireTenantContext(WithTenantContext(context.Background(), tenantContext))
	require.NoError(t, err)
	require.Equal(t, tenantContext.TenantID, got.TenantID)

	_, err = RequireTenantContext(context.Background())
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrTenantContextRequired))
}
