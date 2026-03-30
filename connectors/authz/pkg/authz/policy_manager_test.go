package authz

import (
	"context"
	"strings"
	"testing"

	"github.com/lamassuiot/authz/pkg/models"
	"gocloud.dev/blob/memblob"
)

func TestPolicyManager_CreatePolicy_RejectsRepeatedVertexPath(t *testing.T) {
	bucket := memblob.OpenBucket(nil)
	defer bucket.Close()

	manager := NewPolicyManager(bucket)
	policy := policyWithRepeatedVertexPath("create-invalid")

	err := manager.CreatePolicy(context.Background(), policy)
	if err == nil {
		t.Fatalf("expected create policy to fail for repeated vertex path")
	}

	if !strings.Contains(err.Error(), "simple") || !strings.Contains(err.Error(), "repeated") {
		t.Fatalf("expected simple-path repeated-vertex error, got: %v", err)
	}
}

func TestPolicyManager_UpdatePolicy_RejectsRepeatedVertexPath(t *testing.T) {
	bucket := memblob.OpenBucket(nil)
	defer bucket.Close()

	manager := NewPolicyManager(bucket)

	validPolicy := &models.Policy{
		ID:   "update-invalid",
		Name: "Valid Policy",
		Rules: []*models.Rule{
			{
				Namespace:  "iot",
				SchemaName: "public",
				EntityType: "organization",
				Actions:    []string{"read"},
			},
		},
	}

	if err := manager.CreatePolicy(context.Background(), validPolicy); err != nil {
		t.Fatalf("failed to create initial valid policy: %v", err)
	}

	validPolicy.Rules[0].Relations = policyWithRepeatedVertexPath("tmp").Rules[0].Relations
	err := manager.UpdatePolicy(context.Background(), validPolicy)
	if err == nil {
		t.Fatalf("expected update policy to fail for repeated vertex path")
	}

	if !strings.Contains(err.Error(), "simple") || !strings.Contains(err.Error(), "repeated") {
		t.Fatalf("expected simple-path repeated-vertex error, got: %v", err)
	}
}

func TestPolicyManager_SearchPolicies(t *testing.T) {
	bucket := memblob.OpenBucket(nil)
	defer bucket.Close()

	manager := NewPolicyManager(bucket)

	policies := []*models.Policy{
		{ID: "alpha-001", Name: "Alpha Policy", Description: "handles alpha entities", Rules: []*models.Rule{{Namespace: "iot", SchemaName: "public", EntityType: "organization", Actions: []string{"read"}}}},
		{ID: "beta-002", Name: "Beta Control", Description: "beta scope management", Rules: []*models.Rule{{Namespace: "iot", SchemaName: "public", EntityType: "organization", Actions: []string{"read"}}}},
		{ID: "gamma-003", Name: "Gamma Rules", Description: "irrelevant notes", Rules: []*models.Rule{{Namespace: "iot", SchemaName: "public", EntityType: "organization", Actions: []string{"read"}}}},
	}

	for _, p := range policies {
		if err := manager.CreatePolicy(context.Background(), p); err != nil {
			t.Fatalf("setup: failed to create policy %s: %v", p.ID, err)
		}
	}

	tests := []struct {
		name     string
		query    string
		wantIDs  []string
		wantNone bool
	}{
		{name: "empty query returns all", query: "", wantIDs: []string{"alpha-001", "beta-002", "gamma-003"}},
		{name: "match by ID exact", query: "alpha-001", wantIDs: []string{"alpha-001"}},
		{name: "match by ID partial", query: "beta", wantIDs: []string{"beta-002"}},
		{name: "match by name", query: "Gamma Rules", wantIDs: []string{"gamma-003"}},
		{name: "match by name case-insensitive", query: "ALPHA POLICY", wantIDs: []string{"alpha-001"}},
		{name: "match by description", query: "alpha entities", wantIDs: []string{"alpha-001"}},
		{name: "match by description case-insensitive", query: "BETA SCOPE", wantIDs: []string{"beta-002"}},
		{name: "match multiple via description", query: "management", wantIDs: []string{"beta-002"}},
		{name: "no match returns empty", query: "zzz-no-match", wantNone: true},
		{name: "partial match across fields", query: "001", wantIDs: []string{"alpha-001"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := manager.SearchPolicies(context.Background(), tt.query)
			if err != nil {
				t.Fatalf("SearchPolicies(%q) returned error: %v", tt.query, err)
			}

			if tt.wantNone {
				if len(results) != 0 {
					t.Fatalf("expected no results, got %d", len(results))
				}
				return
			}

			gotIDs := make(map[string]bool, len(results))
			for _, p := range results {
				gotIDs[p.ID] = true
			}

			for _, wantID := range tt.wantIDs {
				if !gotIDs[wantID] {
					t.Errorf("expected policy %s in results, but it was missing; got IDs: %v", wantID, gotIDs)
				}
			}

			if len(results) != len(tt.wantIDs) {
				t.Errorf("expected %d results, got %d", len(tt.wantIDs), len(results))
			}
		})
	}
}

func policyWithRepeatedVertexPath(id string) *models.Policy {
	return &models.Policy{
		ID:   id,
		Name: "Policy With Repeated Vertex",
		Rules: []*models.Rule{
			{
				Namespace:  "iot",
				SchemaName: "public",
				EntityType: "organization",
				Actions:    []string{"read"},
				Relations: []models.RelationRule{
					{
						ToSchemaName: "public",
						ToEntityType: "building",
						Via:          "organization_id",
						Actions:      []string{"read"},
						Relations: []models.RelationRule{
							{
								ToSchemaName: "public",
								ToEntityType: "organization",
								Via:          "parent_org_id",
								Actions:      []string{"read"},
							},
						},
					},
				},
			},
		},
	}
}
