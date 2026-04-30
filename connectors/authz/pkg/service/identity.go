package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/lamassuiot/authz/pkg/engine"
	"github.com/lamassuiot/authz/pkg/models"
)

// ErrNoMatch is returned by IdentityResolver when auth material matches no active principals.
var ErrNoMatch = errors.New("no matching principals found")

// IdentityResolver is the single entry point for the "match auth material → load policies" flow.
type IdentityResolver struct {
	match    principalMatcher
	grants   engine.GrantStore
	policies policyLoader
}

// principalMatcher is the local interface for the MatchService.
type principalMatcher interface {
	MatchPrincipals(ctx context.Context, authMaterial interface{}, authType string) ([]string, error)
}

// policyLoader is the local interface for PolicyManager used by IdentityResolver.
type policyLoader interface {
	GetPolicy(ctx context.Context, policyID string) (*models.Policy, error)
}

// NewIdentityResolver wires a MatchService, GrantStore, and PolicyManager into a resolver.
func NewIdentityResolver(match principalMatcher, grants engine.GrantStore, policies policyLoader) *IdentityResolver {
	return &IdentityResolver{match: match, grants: grants, policies: policies}
}

// Resolve matches auth material to active principals, loads all their granted policies,
// and returns a populated PolicyRegistry ready for Engine.Authorize or Engine.GetListFilter.
// Returns ErrNoMatch (check with errors.Is) when no principals matched.
func (r *IdentityResolver) Resolve(ctx context.Context, authMaterial interface{}, authType string) (*engine.PolicyRegistry, []string, error) {
	principalIDs, err := r.match.MatchPrincipals(ctx, authMaterial, authType)
	if err != nil {
		return nil, nil, fmt.Errorf("match principals: %w", err)
	}
	if len(principalIDs) == 0 {
		return nil, nil, ErrNoMatch
	}

	registry := engine.NewPolicyRegistry()
	for _, pid := range principalIDs {
		grants, err := r.grants.ListForPrincipal(ctx, pid)
		if err != nil {
			return nil, nil, fmt.Errorf("get policies for principal %s: %w", pid, err)
		}
		for _, g := range grants {
			policy, err := r.policies.GetPolicy(ctx, g.PolicyID)
			if err != nil {
				return nil, nil, fmt.Errorf("load policy %s: %w", g.PolicyID, err)
			}
			if err := registry.AddPolicy(policy); err != nil {
				return nil, nil, fmt.Errorf("register policy %s: %w", g.PolicyID, err)
			}
		}
	}
	return registry, principalIDs, nil
}

// GetPoliciesForPrincipal loads policies for a single known principal ID and returns
// a populated PolicyRegistry. Used by the by-ID authorization path.
func (r *IdentityResolver) GetPoliciesForPrincipal(ctx context.Context, principalID string) (*engine.PolicyRegistry, error) {
	grants, err := r.grants.ListForPrincipal(ctx, principalID)
	if err != nil {
		return nil, fmt.Errorf("get policies for principal %s: %w", principalID, err)
	}

	registry := engine.NewPolicyRegistry()
	for _, g := range grants {
		policy, err := r.policies.GetPolicy(ctx, g.PolicyID)
		if err != nil {
			return nil, fmt.Errorf("load policy %s: %w", g.PolicyID, err)
		}
		if err := registry.AddPolicy(policy); err != nil {
			return nil, fmt.Errorf("register policy %s: %w", g.PolicyID, err)
		}
	}
	return registry, nil
}

// MatchPrincipals delegates to the underlying MatchService. Useful for callers that need
// the principal IDs without loading policies (e.g. capabilities controller).
func (r *IdentityResolver) MatchPrincipals(ctx context.Context, authMaterial interface{}, authType string) ([]string, error) {
	return r.match.MatchPrincipals(ctx, authMaterial, authType)
}
