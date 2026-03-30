package authz

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/lamassuiot/authz/pkg/core"
)

type AuthzImplementation struct {
	engine           *Engine
	principalManager *PrincipalManager
	policyManager    *PolicyManager
}

func NewAuthzService(engine *Engine, principalManager *PrincipalManager, policyManager *PolicyManager) core.AuthzEngine {
	return &AuthzImplementation{
		engine:           engine,
		principalManager: principalManager,
		policyManager:    policyManager,
	}
}

func (s *AuthzImplementation) Authorize(principalID, namespace, schemaName, action, entityType string, entityKey map[string]string) (bool, error) {
	ctx := context.Background()

	log.Printf("[AUTHZ] ========== Authorization Request ==========")
	log.Printf("[AUTHZ] Principal: %s", principalID)
	log.Printf("[AUTHZ] Namespace: %s", namespace)
	log.Printf("[AUTHZ] Schema: %s", schemaName)
	log.Printf("[AUTHZ] Action: %s", action)
	log.Printf("[AUTHZ] Entity Type: %s", entityType)
	log.Printf("[AUTHZ] Entity Key: %v", entityKey)
	log.Printf("[AUTHZ] ============================================")

	// Get policy IDs for the principal
	log.Printf("[AUTHZ] Loading policies for principal '%s'...", principalID)
	policyIDs, err := s.principalManager.GetPrincipalPolicies(principalID)
	if err != nil {
		log.Printf("[AUTHZ] ✗ ERROR: Failed to get principal policies: %v", err)
		return false, fmt.Errorf("failed to get principal policies: %w", err)
	}
	log.Printf("[AUTHZ] Found %d policy/policies for principal", len(policyIDs))

	// Load policies from bucket
	policies := NewPolicyRegistry()
	for i, policyID := range policyIDs {
		log.Printf("[AUTHZ]   Loading policy %d/%d: %s", i+1, len(policyIDs), policyID)
		policy, err := s.policyManager.GetPolicy(ctx, policyID)
		if err != nil {
			log.Printf("[AUTHZ] ✗ ERROR: Failed to load policy %s: %v", policyID, err)
			return false, fmt.Errorf("failed to load policy %s: %w", policyID, err)
		}
		log.Printf("[AUTHZ]   Policy '%s' loaded with %d rule(s)", policy.Name, len(policy.Rules))
		policies.AddPolicy(policy)
	}

	log.Printf("[AUTHZ] Starting authorization check...")
	allowed, err := s.engine.Authorize(policies, namespace, schemaName, action, entityType, entityKey)
	if err != nil {
		log.Printf("[AUTHZ] ✗ ERROR: Authorization check failed: %v", err)
		return false, fmt.Errorf("authorization check failed: %w", err)
	}

	log.Printf("[AUTHZ] ========== Final Result: %v ==========", map[bool]string{true: "GRANTED", false: "DENIED"}[allowed])
	return allowed, nil
}

func (s *AuthzImplementation) GetFilter(principalID, namespace, schemaName, entityType string) (string, error) {
	return "", nil
}

// MatchAndAuthorize checks authorization using authentication material
// to automatically match and authorize a principal
func (s *AuthzImplementation) MatchAndAuthorize(authType, authMaterial, namespace, schemaName, action, entityType string, entityKey map[string]string) (bool, []string, error) {
	ctx := context.Background()

	log.Printf("[AUTHZ] ========== MatchAndAuthorize Request ==========")
	log.Printf("[AUTHZ] Namespace: %s", namespace)
	log.Printf("[AUTHZ] Schema: %s", schemaName)
	log.Printf("[AUTHZ] Action: %s", action)
	log.Printf("[AUTHZ] Entity Type: %s", entityType)
	log.Printf("[AUTHZ] Entity Key: %v", entityKey)

	// Match principals from auth material
	log.Printf("[AUTHZ] Matching principals from authentication material (type=%s)...", authType)
	matchedPrincipals, err := s.principalManager.MatchPrincipals(ctx, authMaterial, authType)
	if err != nil {
		log.Printf("[AUTHZ] ✗ ERROR: Failed to match principals: %v", err)
		return false, nil, fmt.Errorf("failed to match principals: %w", err)
	}

	if len(matchedPrincipals) == 0 {
		log.Printf("[AUTHZ] ✗ DENIED: No matching principals found for the provided token")
		return false, nil, fmt.Errorf("no matching principals found")
	}

	log.Printf("[AUTHZ] Matched %d principal(s): %v", len(matchedPrincipals), matchedPrincipals)

	// Collect all policies from all matched principals
	policies := NewPolicyRegistry()
	for _, principalID := range matchedPrincipals {
		log.Printf("[AUTHZ] Loading policies for principal '%s'...", principalID)
		policyIDs, err := s.principalManager.GetPrincipalPolicies(principalID)
		if err != nil {
			log.Printf("[AUTHZ] ✗ ERROR: Failed to get policies for principal %s: %v", principalID, err)
			return false, nil, fmt.Errorf("failed to get principal policies: %w", err)
		}
		log.Printf("[AUTHZ] Found %d policy/policies for principal '%s'", len(policyIDs), principalID)

		for _, policyID := range policyIDs {
			policy, err := s.policyManager.GetPolicy(ctx, policyID)
			if err != nil {
				log.Printf("[AUTHZ] ✗ ERROR: Failed to load policy %s: %v", policyID, err)
				return false, nil, fmt.Errorf("failed to load policy %s: %w", policyID, err)
			}
			log.Printf("[AUTHZ] Policy '%s' loaded with %d rule(s)", policy.Name, len(policy.Rules))
			policies.AddPolicy(policy)
		}
	}

	// Check authorization with combined policies (OR logic)
	log.Printf("[AUTHZ] Checking authorization with combined policies...")
	allowed, err := s.engine.Authorize(policies, namespace, schemaName, action, entityType, entityKey)
	if err != nil {
		log.Printf("[AUTHZ] ✗ ERROR: Authorization check failed: %v", err)
		return false, nil, fmt.Errorf("authorization check failed: %w", err)
	}

	log.Printf("[AUTHZ] ========== Final Result: %v ==========", map[bool]string{true: "GRANTED", false: "DENIED"}[allowed])
	return allowed, matchedPrincipals, nil
}

// MatchAndGetFilter retrieves a SQL filter using authentication material
// to automatically match a principal and generate the appropriate filter
func (s *AuthzImplementation) MatchAndGetFilter(authType, authMaterial, namespace, schemaName, entityType string) (string, []string, error) {
	ctx := context.Background()

	log.Printf("[AUTHZ] MatchAndGetFilter namespace: %s", namespace)

	// Match principals from auth material
	matchedPrincipals, err := s.principalManager.MatchPrincipals(ctx, authMaterial, authType)
	if err != nil {
		return "", nil, fmt.Errorf("failed to match principals: %w", err)
	}

	if len(matchedPrincipals) == 0 {
		return "", nil, fmt.Errorf("no matching principals found")
	}

	// Collect all policies from all matched principals
	policies := NewPolicyRegistry()
	for _, principalID := range matchedPrincipals {
		policyIDs, err := s.principalManager.GetPrincipalPolicies(principalID)
		if err != nil {
			return "", nil, fmt.Errorf("failed to get principal policies: %w", err)
		}

		for _, policyID := range policyIDs {
			policy, err := s.policyManager.GetPolicy(ctx, policyID)
			if err != nil {
				return "", nil, fmt.Errorf("failed to load policy %s: %w", policyID, err)
			}
			policies.AddPolicy(policy)
		}
	}

	// Generate filter with combined policies (OR logic)
	filterSQL, err := s.engine.GetListFilter(policies, namespace, schemaName, entityType)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate filter: %w", err)
	}

	// Extract WHERE clause from the full SQL
	// The filterSQL is "SELECT * FROM table [JOINs] WHERE conditions"
	whereClause := ""
	if whereIdx := strings.Index(filterSQL, "WHERE "); whereIdx != -1 {
		whereClause = filterSQL[whereIdx+6:] // +6 to skip "WHERE "
	}

	return whereClause, matchedPrincipals, nil
}
