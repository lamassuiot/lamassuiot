package service

import (
	"context"
	"fmt"
	"strings"
	"uuid"

	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/engine"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/store"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
)

// SystemPolicyPrefix marks policies managed by Lamassu itself. They are only
// created by the preload at startup and cannot be created, updated or deleted
// through the API.
const SystemPolicyPrefix = "lamassu."

// IsSystemPolicy reports whether policyID belongs to a system-managed policy.
func IsSystemPolicy(policyID string) bool {
	return strings.HasPrefix(policyID, SystemPolicyPrefix)
}

// PolicyManager manages policy storage and retrieval via a PolicyStore.
type PolicyManager struct {
	store   store.PolicyStore
	schemas *engine.SchemaRegistry
}

// PolicyManagerOption configures a PolicyManager.
type PolicyManagerOption func(*PolicyManager)

// WithPolicySchemas makes Create/UpdatePolicy reject relation vias the schemas do not declare
// (see engine.ValidatePolicyAgainstSchemas). Without it only the policy's structure is validated.
func WithPolicySchemas(schemas *engine.SchemaRegistry) PolicyManagerOption {
	return func(pm *PolicyManager) { pm.schemas = schemas }
}

// NewPolicyManager creates a new PolicyManager backed by the given store.
func NewPolicyManager(ps store.PolicyStore, opts ...PolicyManagerOption) *PolicyManager {
	pm := &PolicyManager{store: ps}
	for _, opt := range opts {
		opt(pm)
	}
	return pm
}

func (pm *PolicyManager) validate(policy *models.Policy) error {
	if err := engine.ValidatePolicyStruct(policy); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}
	if pm.schemas != nil {
		if err := engine.ValidatePolicyAgainstSchemas(policy, pm.schemas); err != nil {
			return fmt.Errorf("invalid policy: %w", err)
		}
	}
	return nil
}

func (pm *PolicyManager) CreatePolicy(ctx context.Context, policy *models.Policy) error {
	if policy.ID == "" {
		policy.ID = uuid.NewV7().String()
	}
	if err := pm.validate(policy); err != nil {
		return err
	}
	return pm.store.Create(ctx, policy)
}

func (pm *PolicyManager) GetPolicy(ctx context.Context, policyID string) (*models.Policy, error) {
	return pm.store.Get(ctx, policyID)
}

func (pm *PolicyManager) UpdatePolicy(ctx context.Context, policy *models.Policy) error {
	if IsSystemPolicy(policy.ID) {
		return fmt.Errorf("system-managed policy %q cannot be updated", policy.ID)
	}
	if err := pm.validate(policy); err != nil {
		return err
	}
	return pm.store.Update(ctx, policy)
}

func (pm *PolicyManager) DeletePolicy(ctx context.Context, policyID string) error {
	if IsSystemPolicy(policyID) {
		return fmt.Errorf("system-managed policy %q cannot be deleted", policyID)
	}
	return pm.store.Delete(ctx, policyID)
}

func (pm *PolicyManager) ListPolicies(ctx context.Context, queryParams *resources.QueryParameters) ([]*models.Policy, string, error) {
	return pm.store.List(ctx, queryParams)
}

func (pm *PolicyManager) SearchPolicies(ctx context.Context, query string) ([]*models.Policy, error) {
	return pm.store.Search(ctx, query)
}
