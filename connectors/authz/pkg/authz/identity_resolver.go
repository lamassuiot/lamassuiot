package authz

import (
	"context"
	"errors"
	"fmt"
)

// ErrNoMatch is returned by IdentityResolver when auth material matches no active principals.
var ErrNoMatch = errors.New("no matching principals found")

// IdentityResolver is the single entry point for the "match auth material → load policies"
// flow. It collapses the pattern that was previously copy-pasted across four call sites.
type IdentityResolver struct {
	match    *MatchService
	grants   GrantStore
	policies *PolicyManager
}

// NewIdentityResolver wires a MatchService, GrantStore, and PolicyManager into a resolver.
func NewIdentityResolver(match *MatchService, grants GrantStore, policies *PolicyManager) *IdentityResolver {
	return &IdentityResolver{match: match, grants: grants, policies: policies}
}

// Resolve matches auth material to active principals, loads all their granted policies,
// and returns a populated PolicyRegistry ready for Engine.Authorize or Engine.GetListFilter.
// Returns ErrNoMatch (check with errors.Is) when no principals matched.
func (r *IdentityResolver) Resolve(ctx context.Context, authMaterial interface{}, authType string) (*PolicyRegistry, []string, error) {
	principalIDs, err := r.match.MatchPrincipals(ctx, authMaterial, authType)
	if err != nil {
		return nil, nil, fmt.Errorf("match principals: %w", err)
	}
	if len(principalIDs) == 0 {
		return nil, nil, ErrNoMatch
	}

	registry := NewPolicyRegistry()
	for _, pid := range principalIDs {
		policyIDs, err := r.grants.ListForPrincipal(ctx, pid)
		if err != nil {
			return nil, nil, fmt.Errorf("get policies for principal %s: %w", pid, err)
		}
		for _, id := range policyIDs {
			policy, err := r.policies.GetPolicy(ctx, id)
			if err != nil {
				return nil, nil, fmt.Errorf("load policy %s: %w", id, err)
			}
			if err := registry.AddPolicy(policy); err != nil {
				return nil, nil, fmt.Errorf("register policy %s: %w", id, err)
			}
		}
	}
	return registry, principalIDs, nil
}

// GetPoliciesForPrincipal loads policies for a single known principal ID and returns
// a populated PolicyRegistry. Used by the by-ID authorization path (Authorize, GetFilter).
func (r *IdentityResolver) GetPoliciesForPrincipal(ctx context.Context, principalID string) (*PolicyRegistry, error) {
	policyIDs, err := r.grants.ListForPrincipal(ctx, principalID)
	if err != nil {
		return nil, fmt.Errorf("get policies for principal %s: %w", principalID, err)
	}

	registry := NewPolicyRegistry()
	for _, id := range policyIDs {
		policy, err := r.policies.GetPolicy(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("load policy %s: %w", id, err)
		}
		if err := registry.AddPolicy(policy); err != nil {
			return nil, fmt.Errorf("register policy %s: %w", id, err)
		}
	}
	return registry, nil
}

// MatchPrincipals delegates to the underlying MatchService. Useful for callers that need
// the principal IDs without loading policies (e.g. capabilities controller).
func (r *IdentityResolver) MatchPrincipals(ctx context.Context, authMaterial interface{}, authType string) ([]string, error) {
	return r.match.MatchPrincipals(ctx, authMaterial, authType)
}
