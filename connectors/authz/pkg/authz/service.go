package authz

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/lamassuiot/authz/pkg/core"
)

type AuthzImplementation struct {
	engine           *Engine
	principalManager *PrincipalManager
	policyManager    *PolicyManager
	resolver         *IdentityResolver
}

func NewAuthzService(engine *Engine, principalManager *PrincipalManager, policyManager *PolicyManager) core.AuthzEngine {
	resolver := NewIdentityResolver(
		principalManager.matchService,
		principalManager.store,
		policyManager,
	)
	return &AuthzImplementation{
		engine:           engine,
		principalManager: principalManager,
		policyManager:    policyManager,
		resolver:         resolver,
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

	log.Printf("[AUTHZ] Loading policies for principal '%s'...", principalID)
	policies, err := s.resolver.GetPoliciesForPrincipal(ctx, principalID)
	if err != nil {
		log.Printf("[AUTHZ] ✗ ERROR: Failed to get principal policies: %v", err)
		return false, fmt.Errorf("failed to get principal policies: %w", err)
	}
	log.Printf("[AUTHZ] Policies loaded for principal")

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
// to automatically match a principal and check authorization.
func (s *AuthzImplementation) MatchAndAuthorize(authType, authMaterial, namespace, schemaName, action, entityType string, entityKey map[string]string) (bool, []string, error) {
	ctx := context.Background()

	log.Printf("[AUTHZ] ========== MatchAndAuthorize Request ==========")
	log.Printf("[AUTHZ] Namespace: %s", namespace)
	log.Printf("[AUTHZ] Schema: %s", schemaName)
	log.Printf("[AUTHZ] Action: %s", action)
	log.Printf("[AUTHZ] Entity Type: %s", entityType)
	log.Printf("[AUTHZ] Entity Key: %v", entityKey)

	log.Printf("[AUTHZ] Resolving principals and policies (type=%s)...", authType)
	policies, matchedPrincipals, err := s.resolver.Resolve(ctx, authMaterial, authType)
	if err != nil {
		if errors.Is(err, ErrNoMatch) {
			log.Printf("[AUTHZ] ✗ DENIED: No matching principals found for the provided token")
			return false, nil, fmt.Errorf("no matching principals found")
		}
		log.Printf("[AUTHZ] ✗ ERROR: Failed to resolve principals: %v", err)
		return false, nil, fmt.Errorf("failed to resolve principals: %w", err)
	}

	log.Printf("[AUTHZ] Matched %d principal(s): %v", len(matchedPrincipals), matchedPrincipals)

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
// to automatically match a principal and generate the appropriate filter.
func (s *AuthzImplementation) MatchAndGetFilter(authType, authMaterial, namespace, schemaName, entityType string) (string, []string, error) {
	ctx := context.Background()

	log.Printf("[AUTHZ] MatchAndGetFilter namespace: %s", namespace)

	policies, matchedPrincipals, err := s.resolver.Resolve(ctx, authMaterial, authType)
	if err != nil {
		if errors.Is(err, ErrNoMatch) {
			return "", nil, fmt.Errorf("no matching principals found")
		}
		return "", nil, fmt.Errorf("failed to resolve principals: %w", err)
	}

	filterSQL, err := s.engine.GetListFilter(policies, namespace, schemaName, entityType)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate filter: %w", err)
	}

	whereClause := ""
	if whereIdx := strings.Index(filterSQL, "WHERE "); whereIdx != -1 {
		whereClause = filterSQL[whereIdx+6:]
	}

	return whereClause, matchedPrincipals, nil
}
