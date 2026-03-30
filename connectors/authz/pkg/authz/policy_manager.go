package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lamassuiot/authz/pkg/models"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob"
	"gocloud.dev/gcerrors"
)

// PolicyManager manages policy storage and retrieval from blob storage
type PolicyManager struct {
	bucket *blob.Bucket
}

// NewPolicyManager creates a new policy manager
func NewPolicyManager(bucket *blob.Bucket) *PolicyManager {
	return &PolicyManager{
		bucket: bucket,
	}
}

// CreatePolicy creates a new policy in the blob storage
func (pm *PolicyManager) CreatePolicy(ctx context.Context, policy *models.Policy) error {
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}

	if err := validatePolicyStruct(policy); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}

	// Check if policy already exists
	exists, err := pm.bucket.Exists(ctx, pm.getPolicyKey(policy.ID))
	if err != nil {
		return fmt.Errorf("failed to check if policy exists: %w", err)
	}
	if exists {
		return fmt.Errorf("policy with ID %s already exists", policy.ID)
	}

	// Marshal policy to JSON
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	// Write to blob storage
	err = pm.bucket.WriteAll(ctx, pm.getPolicyKey(policy.ID), data, &blob.WriterOptions{
		ContentType: "application/json",
	})
	if err != nil {
		return fmt.Errorf("failed to write policy to storage: %w", err)
	}

	return nil
}

// GetPolicy retrieves a policy by ID from blob storage
func (pm *PolicyManager) GetPolicy(ctx context.Context, policyID string) (*models.Policy, error) {
	data, err := pm.bucket.ReadAll(ctx, pm.getPolicyKey(policyID))
	if err != nil {
		if gcerrors.Code(err) == gcerrors.NotFound {
			return nil, fmt.Errorf("policy not found: %s", policyID)
		}
		return nil, fmt.Errorf("failed to read policy from storage: %w", err)
	}

	var policy models.Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy: %w", err)
	}

	return &policy, nil
}

// UpdatePolicy updates an existing policy in blob storage
func (pm *PolicyManager) UpdatePolicy(ctx context.Context, policy *models.Policy) error {
	if err := validatePolicyStruct(policy); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}

	// Check if policy exists
	exists, err := pm.bucket.Exists(ctx, pm.getPolicyKey(policy.ID))
	if err != nil {
		return fmt.Errorf("failed to check if policy exists: %w", err)
	}
	if !exists {
		return fmt.Errorf("policy not found: %s", policy.ID)
	}

	// Marshal policy to JSON
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	// Write to blob storage (overwrites existing)
	err = pm.bucket.WriteAll(ctx, pm.getPolicyKey(policy.ID), data, &blob.WriterOptions{
		ContentType: "application/json",
	})
	if err != nil {
		return fmt.Errorf("failed to update policy in storage: %w", err)
	}

	return nil
}

// DeletePolicy deletes a policy from blob storage
func (pm *PolicyManager) DeletePolicy(ctx context.Context, policyID string) error {
	// Check if policy exists
	exists, err := pm.bucket.Exists(ctx, pm.getPolicyKey(policyID))
	if err != nil {
		return fmt.Errorf("failed to check if policy exists: %w", err)
	}
	if !exists {
		return fmt.Errorf("policy not found: %s", policyID)
	}

	// Delete from blob storage
	err = pm.bucket.Delete(ctx, pm.getPolicyKey(policyID))
	if err != nil {
		return fmt.Errorf("failed to delete policy from storage: %w", err)
	}

	return nil
}

// ListPolicies retrieves all policies from blob storage
func (pm *PolicyManager) ListPolicies(ctx context.Context) ([]*models.Policy, error) {
	iter := pm.bucket.List(&blob.ListOptions{
		Prefix: "policies/",
	})

	var policies []*models.Policy
	for {
		obj, err := iter.Next(ctx)
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("failed to iterate policies: %w", err)
		}

		// Read policy data
		data, err := pm.bucket.ReadAll(ctx, obj.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to read policy %s: %w", obj.Key, err)
		}

		var policy models.Policy
		if err := json.Unmarshal(data, &policy); err != nil {
			return nil, fmt.Errorf("failed to unmarshal policy %s: %w", obj.Key, err)
		}

		policies = append(policies, &policy)
	}

	return policies, nil
}

// SearchPolicies retrieves all policies whose ID, Name, or Description contain the given
// query string (case-insensitive). An empty query returns all policies.
func (pm *PolicyManager) SearchPolicies(ctx context.Context, query string) ([]*models.Policy, error) {
	policies, err := pm.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}

	if query == "" {
		return policies, nil
	}

	lower := strings.ToLower(query)
	var matched []*models.Policy
	for _, p := range policies {
		if strings.Contains(strings.ToLower(p.ID), lower) ||
			strings.Contains(strings.ToLower(p.Name), lower) ||
			strings.Contains(strings.ToLower(p.Description), lower) {
			matched = append(matched, p)
		}
	}

	return matched, nil
}

// getPolicyKey generates the blob storage key for a policy
func (pm *PolicyManager) getPolicyKey(policyID string) string {
	return fmt.Sprintf("policies/%s.json", policyID)
}

// PolicyStats represents statistics about a policy
type PolicyStats struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	RuleCount      int       `json:"ruleCount"`
	PrincipalCount int64     `json:"principalCount"`
	LastModified   time.Time `json:"lastModified,omitempty"`
	SizeBytes      int64     `json:"sizeBytes,omitempty"`
}

// GetPolicyStats retrieves statistics about a policy
func (pm *PolicyManager) GetPolicyStats(ctx context.Context, policyID string, principalManager *PrincipalManager) (*PolicyStats, error) {
	policy, err := pm.GetPolicy(ctx, policyID)
	if err != nil {
		return nil, err
	}

	stats := &PolicyStats{
		ID:        policy.ID,
		Name:      policy.Name,
		RuleCount: len(policy.Rules),
	}

	// Get principal count if principal manager is provided
	if principalManager != nil {
		count, err := principalManager.CountPolicyPrincipals(policyID)
		if err == nil {
			stats.PrincipalCount = count
		}
	}

	// Get blob metadata
	attrs, err := pm.bucket.Attributes(ctx, pm.getPolicyKey(policyID))
	if err == nil {
		stats.LastModified = attrs.ModTime
		stats.SizeBytes = attrs.Size
	}

	return stats, nil
}
