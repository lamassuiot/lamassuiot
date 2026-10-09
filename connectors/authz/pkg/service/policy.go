package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lamassuiot/authz/pkg/engine"
	"github.com/lamassuiot/authz/pkg/models"
	"github.com/lamassuiot/authz/pkg/store"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
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
	store store.PolicyStore
}

// NewPolicyManager creates a new PolicyManager backed by the given store.
func NewPolicyManager(ps store.PolicyStore) *PolicyManager {
	return &PolicyManager{store: ps}
}

func (pm *PolicyManager) CreatePolicy(ctx context.Context, policy *models.Policy) error {
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}
	if err := engine.ValidatePolicyStruct(policy); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
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
	if err := engine.ValidatePolicyStruct(policy); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
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
