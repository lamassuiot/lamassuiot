package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/lamassuiot/authz/pkg/core"
	"github.com/lamassuiot/authz/pkg/engine"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/sirupsen/logrus"
)

// AuthzImplementation is the thin orchestration layer implementing core.AuthzEngine.
type AuthzImplementation struct {
	engine           *engine.Engine
	principalManager *PrincipalManager
	policyManager    *PolicyManager
	resolver         *IdentityResolver
	logger           *logrus.Entry
}

// ServiceOption is a functional option for AuthzImplementation.
type ServiceOption func(*AuthzImplementation)

// WithServiceLogger injects a logrus.Entry into the AuthzImplementation.
func WithServiceLogger(l *logrus.Entry) ServiceOption {
	return func(s *AuthzImplementation) { s.logger = l }
}

func serviceNopLogger() *logrus.Entry {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return logrus.NewEntry(l)
}

// NewAuthzService creates an AuthzImplementation that satisfies core.AuthzEngine.
func NewAuthzService(e *engine.Engine, principalManager *PrincipalManager, policyManager *PolicyManager, opts ...ServiceOption) core.AuthzEngine {
	resolver := NewIdentityResolver(
		principalManager.matchService,
		principalManager.store,
		policyManager,
	)
	s := &AuthzImplementation{
		engine:           e,
		principalManager: principalManager,
		policyManager:    policyManager,
		resolver:         resolver,
		logger:           serviceNopLogger(),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

func (s *AuthzImplementation) Authorize(ctx context.Context, principalID, namespace, schemaName, action, entityType string, entityKey map[string]string) (bool, error) {
	log := helpers.ConfigureLogger(ctx, s.logger)

	policies, err := s.resolver.GetPoliciesForPrincipal(ctx, principalID)
	if err != nil {
		return false, fmt.Errorf("failed to get principal policies: %w", err)
	}

	allowed, err := s.engine.Authorize(ctx, policies, namespace, schemaName, action, entityType, entityKey)
	if err != nil {
		return false, fmt.Errorf("authorization check failed: %w", err)
	}

	reason := "denied: no applicable policy"
	if allowed {
		reason = "allowed by policy"
	}
	log.WithFields(logrus.Fields{
		"principal_id": principalID,
		"namespace":    namespace,
		"schema":       schemaName,
		"entity_type":  entityType,
		"action":       action,
		"allowed":      allowed,
		"policy_count": len(policies.GetAll()),
		"reason":       reason,
	}).Info("authorization decision")

	return allowed, nil
}

func (s *AuthzImplementation) GetFilter(ctx context.Context, principalID, namespace, schemaName, entityType string) (string, error) {
	log := helpers.ConfigureLogger(ctx, s.logger)

	policies, err := s.resolver.GetPoliciesForPrincipal(ctx, principalID)
	if err != nil {
		return "", fmt.Errorf("failed to get principal policies: %w", err)
	}

	filterSQL, err := s.engine.GetListFilter(ctx, policies, namespace, schemaName, entityType)
	if err != nil {
		return "", err
	}

	log.WithFields(logrus.Fields{
		"principal_id": principalID,
		"namespace":    namespace,
		"schema":       schemaName,
		"entity_type":  entityType,
		"policy_count": len(policies.GetAll()),
	}).Debug("list filter generated")

	return filterSQL, nil
}

func (s *AuthzImplementation) MatchAndAuthorize(ctx context.Context, authType, authMaterial, namespace, schemaName, action, entityType string, entityKey map[string]string) (bool, []string, error) {
	log := helpers.ConfigureLogger(ctx, s.logger)

	policies, matchedPrincipals, err := s.resolver.Resolve(ctx, authMaterial, authType)
	if err != nil {
		if errors.Is(err, ErrNoMatch) {
			return false, nil, fmt.Errorf("no matching principals found")
		}
		return false, nil, fmt.Errorf("failed to resolve principals: %w", err)
	}

	log.WithFields(logrus.Fields{
		"matched_count":      len(matchedPrincipals),
		"matched_principals": matchedPrincipals,
		"auth_type":          authType,
	}).Debug("resolved principals")

	allowed, err := s.engine.Authorize(ctx, policies, namespace, schemaName, action, entityType, entityKey)
	if err != nil {
		return false, nil, fmt.Errorf("authorization check failed: %w", err)
	}

	reason := "denied: no applicable policy"
	if allowed {
		reason = "allowed by policy"
	}
	log.WithFields(logrus.Fields{
		"matched_count": len(matchedPrincipals),
		"auth_type":     authType,
		"namespace":     namespace,
		"schema":        schemaName,
		"entity_type":   entityType,
		"action":        action,
		"allowed":       allowed,
		"policy_count":  len(policies.GetAll()),
		"reason":        reason,
	}).Info("authorization decision")

	return allowed, matchedPrincipals, nil
}

func (s *AuthzImplementation) MatchAndGetFilter(ctx context.Context, authType, authMaterial, namespace, schemaName, entityType string) (string, []string, error) {
	log := helpers.ConfigureLogger(ctx, s.logger)

	policies, matchedPrincipals, err := s.resolver.Resolve(ctx, authMaterial, authType)
	if err != nil {
		if errors.Is(err, ErrNoMatch) {
			return "", nil, fmt.Errorf("no matching principals found")
		}
		return "", nil, fmt.Errorf("failed to resolve principals: %w", err)
	}

	filterSQL, err := s.engine.GetListFilter(ctx, policies, namespace, schemaName, entityType)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate filter: %w", err)
	}

	whereClause := ""
	if whereIdx := strings.Index(filterSQL, "WHERE "); whereIdx != -1 {
		whereClause = filterSQL[whereIdx+6:]
	}

	log.WithFields(logrus.Fields{
		"matched_count":      len(matchedPrincipals),
		"matched_principals": matchedPrincipals,
		"auth_type":          authType,
		"namespace":          namespace,
		"schema":             schemaName,
		"entity_type":        entityType,
		"policy_count":       len(policies.GetAll()),
	}).Debug("list filter generated")

	return whereClause, matchedPrincipals, nil
}
