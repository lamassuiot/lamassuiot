package service

import (
	"context"

	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

// PrincipalService is the interface satisfied by PrincipalManager and its decorators.
type PrincipalService interface {
	CreatePrincipal(ctx context.Context, p *models.Principal) error
	GetPrincipal(ctx context.Context, id string) (*models.Principal, error)
	GetPrincipalWithPolicies(ctx context.Context, id string) (*models.Principal, error)
	ListPrincipals(ctx context.Context, queryParams *resources.QueryParameters) ([]*models.Principal, string, error)
	UpdatePrincipal(ctx context.Context, p *models.Principal) error
	DeletePrincipal(ctx context.Context, id string) error
	GrantPolicy(ctx context.Context, principalID, policyID, grantedBy string) error
	RevokePolicy(ctx context.Context, principalID, policyID string) error
	GetPrincipalPolicies(ctx context.Context, principalID string, queryParams *resources.QueryParameters) ([]models.PrincipalPolicy, string, error)
	CountPolicyPrincipals(ctx context.Context, policyID string) (int64, error)
}

// PolicyService is the interface satisfied by PolicyManager and its decorators.
type PolicyService interface {
	CreatePolicy(ctx context.Context, policy *models.Policy) error
	GetPolicy(ctx context.Context, policyID string) (*models.Policy, error)
	UpdatePolicy(ctx context.Context, policy *models.Policy) error
	DeletePolicy(ctx context.Context, policyID string) error
	ListPolicies(ctx context.Context, queryParams *resources.QueryParameters) ([]*models.Policy, string, error)
	SearchPolicies(ctx context.Context, query string) ([]*models.Policy, error)
}

// Verify that concrete types satisfy the interfaces at compile time.
var _ PrincipalService = (*PrincipalManager)(nil)
var _ PolicyService = (*PolicyManager)(nil)
