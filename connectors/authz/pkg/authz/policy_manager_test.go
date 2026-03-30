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
