package service

import (
	"context"
	"errors"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/engine"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubMatcher struct {
	principals []string
}

func (m *stubMatcher) MatchPrincipals(_ context.Context, _ any, _ string) ([]string, error) {
	return m.principals, nil
}

type stubGrantStore struct {
	engine.GrantStore
	grants map[string][]models.PrincipalPolicy
}

func (s *stubGrantStore) ListForPrincipal(_ context.Context, principalID string, _ *resources.QueryParameters) ([]models.PrincipalPolicy, string, error) {
	return s.grants[principalID], "", nil
}

type stubPolicyLoader struct {
	policies map[string]*models.Policy
}

func (l *stubPolicyLoader) GetPolicy(_ context.Context, policyID string) (*models.Policy, error) {
	return l.policies[policyID], nil
}

type stubTenantChecker struct {
	memberships map[string]map[string]bool // tenantID -> principalID -> allowed
}

func (c *stubTenantChecker) IsPrincipalInTenant(_ context.Context, tenantID, principalID string) (bool, error) {
	return c.memberships[tenantID][principalID], nil
}

func TestIdentityResolverFiltersPrincipalsByTenant(t *testing.T) {
	adminPolicy := &models.Policy{
		ID:   "pol-admin",
		Name: "Admin",
		Rules: []*models.Rule{
			{Namespace: "pki", SchemaName: "ca", EntityType: "ca_certificate", Actions: []string{"create", "read"}, DirectGrants: []string{"*"}},
		},
	}
	viewerPolicy := &models.Policy{
		ID:   "pol-viewer",
		Name: "Viewer",
		Rules: []*models.Rule{
			{Namespace: "pki", SchemaName: "ca", EntityType: "ca_certificate", Actions: []string{"read"}, DirectGrants: []string{"*"}},
		},
	}

	resolver := NewIdentityResolver(
		&stubMatcher{principals: []string{"p-tenant-a-admin", "p-tenant-b-viewer"}},
		&stubGrantStore{
			grants: map[string][]models.PrincipalPolicy{
				"p-tenant-a-admin":  {{PrincipalID: "p-tenant-a-admin", PolicyID: "pol-admin"}},
				"p-tenant-b-viewer": {{PrincipalID: "p-tenant-b-viewer", PolicyID: "pol-viewer"}},
			},
		},
		&stubPolicyLoader{
			policies: map[string]*models.Policy{
				"pol-admin":  adminPolicy,
				"pol-viewer": viewerPolicy,
			},
		},
	)
	resolver.SetTenantPrincipalChecker(&stubTenantChecker{
		memberships: map[string]map[string]bool{
			"tenant-a": {"p-tenant-a-admin": true},
			"tenant-b": {"p-tenant-b-viewer": true},
		},
	})

	t.Run("loads only policies of principals associated with tenant-b", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), core.LamassuContextKeyTenantID, "tenant-b")
		registry, principals, err := resolver.Resolve(ctx, "jwt", "oidc")
		require.NoError(t, err)
		assert.Equal(t, []string{"p-tenant-b-viewer"}, principals)
		require.Len(t, registry.GetAll(), 1)
		assert.Equal(t, "pol-viewer", registry.GetAll()[0].ID)
	})

	t.Run("denies with ErrTenantAccessDenied when credential matches no principal in tenant-c", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), core.LamassuContextKeyTenantID, "tenant-c")
		_, _, err := resolver.Resolve(ctx, "jwt", "oidc")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrTenantAccessDenied))
		assert.False(t, errors.Is(err, ErrNoMatch))
	})

	t.Run("GetPoliciesForPrincipal rejects principal from another tenant", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), core.LamassuContextKeyTenantID, "tenant-b")
		_, err := resolver.GetPoliciesForPrincipal(ctx, "p-tenant-a-admin")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrTenantAccessDenied))
	})

	t.Run("unknown credential still returns ErrNoMatch", func(t *testing.T) {
		emptyResolver := NewIdentityResolver(&stubMatcher{principals: nil}, &stubGrantStore{}, &stubPolicyLoader{})
		emptyResolver.SetTenantPrincipalChecker(&stubTenantChecker{})
		ctx := context.WithValue(context.Background(), core.LamassuContextKeyTenantID, "tenant-a")
		_, _, err := emptyResolver.Resolve(ctx, "jwt", "oidc")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrNoMatch))
	})
}
