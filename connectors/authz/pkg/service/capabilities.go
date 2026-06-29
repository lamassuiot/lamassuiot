package service

import (
	"context"
	"fmt"

	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/engine"
	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/models"
	"github.com/sirupsen/logrus"
)

// principalWithPoliciesLoader is the subset of PrincipalService used by capability functions.
type principalWithPoliciesLoader interface {
	GetPrincipalWithPolicies(ctx context.Context, id string) (*models.Principal, error)
}

// policyByIDLoader is the subset of PolicyService used by capability functions.
type policyByIDLoader interface {
	GetPolicy(ctx context.Context, policyID string) (*models.Policy, error)
}

// GetPrincipalPolicies loads policies for a principal.
func GetPrincipalPolicies(ctx context.Context, e *engine.Engine, pm principalWithPoliciesLoader, polm policyByIDLoader, principalID string) (*engine.PolicyRegistry, error) {
	log := e.Logger().WithContext(ctx)
	principal, err := pm.GetPrincipalWithPolicies(ctx, principalID)
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
func GetGlobalCapabilitiesForPrincipal(ctx context.Context, e *engine.Engine, pm principalWithPoliciesLoader, polm policyByIDLoader, principalID string) (engine.GlobalCapabilities, error) {
	policies, err := GetPrincipalPolicies(ctx, e, pm, polm, principalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal policies: %w", err)
	}
	return e.GetGlobalCapabilities(ctx, policies)
}

// GetEntityCapabilitiesForPrincipal loads the principal's policies and returns the atomic
// actions granted on the specified entity instance.
func GetEntityCapabilitiesForPrincipal(ctx context.Context, e *engine.Engine, pm principalWithPoliciesLoader, polm policyByIDLoader, principalID, namespace, schemaName, entityType string, entityKey map[string]string) (*engine.EntityCapabilities, error) {
	policies, err := GetPrincipalPolicies(ctx, e, pm, polm, principalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal policies: %w", err)
	}
	return e.GetEntityCapabilities(ctx, policies, namespace, schemaName, entityType, entityKey)
}

// GetEntityCapabilitiesBatchForPrincipal loads the principal's policies once and evaluates
// all queries, returning results in the same order as the input.
func GetEntityCapabilitiesBatchForPrincipal(ctx context.Context, e *engine.Engine, pm principalWithPoliciesLoader, polm policyByIDLoader, principalID string, queries []engine.EntityCapabilityQuery) ([]engine.EntityCapabilitiesResult, error) {
	policies, err := GetPrincipalPolicies(ctx, e, pm, polm, principalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal policies: %w", err)
	}
	return e.GetEntityCapabilitiesBatch(ctx, policies, queries), nil
}
