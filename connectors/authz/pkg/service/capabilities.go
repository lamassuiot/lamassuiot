package service

import (
	"context"
	"fmt"

	"github.com/lamassuiot/authz/pkg/engine"
	"github.com/sirupsen/logrus"
)

// GetPrincipalPolicies loads policies for a principal by loading the principal's policy
// grants from the manager and building a PolicyRegistry.
func GetPrincipalPolicies(ctx context.Context, e *engine.Engine, pm *PrincipalManager, polm *PolicyManager, principalID string) (*engine.PolicyRegistry, error) {
	log := e.Logger().WithContext(ctx)
	principal, err := pm.GetPrincipalWithPolicies(principalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal: %w", err)
	}

	registry := engine.NewPolicyRegistry()
	for _, pp := range principal.Policies {
		policy, err := polm.GetPolicy(ctx, pp.PolicyID)
		if err != nil {
			log.WithFields(logrus.Fields{
				"policy_id": pp.PolicyID,
				"error":     err,
			}).Warn("could not load policy")
			continue
		}
		if err := registry.AddPolicy(policy); err != nil {
			log.WithFields(logrus.Fields{
				"policy_id": pp.PolicyID,
				"error":     err,
			}).Warn("could not register policy")
			continue
		}
	}

	return registry, nil
}

// GetGlobalCapabilitiesForPrincipal loads the principal's policies and returns the global
// capabilities across all entity types.
func GetGlobalCapabilitiesForPrincipal(ctx context.Context, e *engine.Engine, pm *PrincipalManager, polm *PolicyManager, principalID string) (engine.GlobalCapabilities, error) {
	policies, err := GetPrincipalPolicies(ctx, e, pm, polm, principalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal policies: %w", err)
	}
	return e.GetGlobalCapabilities(ctx, policies)
}

// GetEntityCapabilitiesForPrincipal loads the principal's policies and returns the atomic
// actions granted on the specified entity instance.
func GetEntityCapabilitiesForPrincipal(ctx context.Context, e *engine.Engine, pm *PrincipalManager, polm *PolicyManager, principalID, namespace, schemaName, entityType string, entityKey map[string]string) (*engine.EntityCapabilities, error) {
	policies, err := GetPrincipalPolicies(ctx, e, pm, polm, principalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal policies: %w", err)
	}
	return e.GetEntityCapabilities(ctx, policies, namespace, schemaName, entityType, entityKey)
}

// GetEntityCapabilitiesBatchForPrincipal loads the principal's policies once and evaluates
// all queries, returning results in the same order as the input.
func GetEntityCapabilitiesBatchForPrincipal(ctx context.Context, e *engine.Engine, pm *PrincipalManager, polm *PolicyManager, principalID string, queries []engine.EntityCapabilityQuery) ([]engine.EntityCapabilitiesResult, error) {
	policies, err := GetPrincipalPolicies(ctx, e, pm, polm, principalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal policies: %w", err)
	}
	return e.GetEntityCapabilitiesBatch(ctx, policies, queries), nil
}
