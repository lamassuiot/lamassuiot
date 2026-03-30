package authz

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lamassuiot/authz/pkg/models"
)

func TestLoadIoTPolicies(t *testing.T) {
	registry := NewPolicyRegistry()

	err := registry.Load("../../examples/iot/policies.json")
	if err != nil {
		t.Fatalf("Failed to load IoT policies: %v", err)
	}

	// Verify all policies are loaded
	policies := registry.GetAll()
	if len(policies) == 0 {
		t.Error("Expected policies to be loaded")
	}

	// Verify we can get rules by entity type
	entityTypes := []string{"public.organization", "public.building", "public.gateway", "public.device"}
	for _, entityType := range entityTypes {
		rule, err := registry.Get(entityType)
		if err != nil {
			t.Errorf("Failed to get rule for %s: %v", entityType, err)
			continue
		}

		if rule.QualifiedEntityType() != entityType {
			t.Errorf("Expected qualified entityType %s, got %s", entityType, rule.QualifiedEntityType())
		}
	}
}

func TestPolicyRegistry_Load(t *testing.T) {
	// Create temp test file
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policies.json")

	content := `[
{
"id": "test-policy-1",
"name": "Test models.Policy",
"description": "A test policy",
"rules": [
{
"namespace": "test",
	"schemaName": "test",
	"entityType": "document",
"actions": ["read", "write"],
"relations": [
{
	"to": {"schemaName": "test", "entityType": "folder"},
"via": "parent",
"actions": ["read"]
}
]
}
]
}
]`

	if err := os.WriteFile(policyFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	registry := NewPolicyRegistry()
	err := registry.Load(policyFile)
	if err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	policies := registry.GetAll()
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	policy := policies[0]
	if policy.ID != "test-policy-1" {
		t.Errorf("Expected ID 'test-policy-1', got '%s'", policy.ID)
	}

	if policy.Name != "Test models.Policy" {
		t.Errorf("Expected name 'Test models.Policy', got '%s'", policy.Name)
	}

	if len(policy.Rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(policy.Rules))
	}

	rule := policy.Rules[0]
	if rule.SchemaName != "test" {
		t.Errorf("Expected schemaName 'test', got '%s'", rule.SchemaName)
	}

	if rule.EntityType != "document" {
		t.Errorf("Expected entityType 'document', got '%s'", rule.EntityType)
	}

	if len(rule.Actions) != 2 {
		t.Errorf("Expected 2 actions, got %d", len(rule.Actions))
	}

	if len(rule.Relations) != 1 {
		t.Errorf("Expected 1 relation, got %d", len(rule.Relations))
	}
}

func TestPolicyRegistry_Get_NotFound(t *testing.T) {
	registry := NewPolicyRegistry()

	_, err := registry.Get("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent rule, got nil")
	}
}

func TestRule_HasAction(t *testing.T) {
	rule := &models.Rule{
		EntityType: "document",
		Actions:    []string{"read", "write", "delete"},
	}

	if !rule.HasAction("read") {
		t.Error("Expected HasAction('read') to be true")
	}

	if !rule.HasAction("write") {
		t.Error("Expected HasAction('write') to be true")
	}

	if rule.HasAction("execute") {
		t.Error("Expected HasAction('execute') to be false")
	}
}

func TestRule_HasAction_Wildcard(t *testing.T) {
	rule := &models.Rule{
		EntityType: "document",
		Actions:    []string{"*"},
	}

	if !rule.HasAction("read") {
		t.Error("Expected HasAction('read') to be true with wildcard action")
	}

	if !rule.HasAction("list") {
		t.Error("Expected HasAction('list') to be true with wildcard action")
	}

	if !rule.HasAction("custom_action") {
		t.Error("Expected HasAction('custom_action') to be true with wildcard action")
	}
}

func TestRule_GetRelationsTo(t *testing.T) {
	rule := &models.Rule{
		EntityType: "device",
		Relations: []models.RelationRule{
			{To: "gateway", Via: "gateway", Actions: []string{"read"}},
			{To: "building", Via: "gateway", Actions: []string{"read"}},
			{To: "gateway", Via: "technician", Actions: []string{"write"}},
		},
	}

	gatewayRels := rule.GetRelationsTo("gateway")
	if len(gatewayRels) != 2 {
		t.Errorf("Expected 2 gateway relations, got %d", len(gatewayRels))
	}

	buildingRels := rule.GetRelationsTo("building")
	if len(buildingRels) != 1 {
		t.Errorf("Expected 1 building relation, got %d", len(buildingRels))
	}

	orgRels := rule.GetRelationsTo("organization")
	if len(orgRels) != 0 {
		t.Errorf("Expected 0 organization relations, got %d", len(orgRels))
	}
}

func TestRelationRule_HasAction(t *testing.T) {
	rel := &models.RelationRule{
		To:      "gateway",
		Via:     "gateway",
		Actions: []string{"read", "control"},
	}

	if !rel.HasAction("read") {
		t.Error("Expected HasAction('read') to be true")
	}

	if !rel.HasAction("control") {
		t.Error("Expected HasAction('control') to be true")
	}

	if rel.HasAction("delete") {
		t.Error("Expected HasAction('delete') to be false")
	}
}

func TestRelationRule_HasAction_Wildcard(t *testing.T) {
	rel := &models.RelationRule{
		To:      "gateway",
		Via:     "gateway",
		Actions: []string{"*"},
	}

	if !rel.HasAction("read") {
		t.Error("Expected HasAction('read') to be true with wildcard action")
	}

	if !rel.HasAction("control") {
		t.Error("Expected HasAction('control') to be true with wildcard action")
	}

	if !rel.HasAction("delete") {
		t.Error("Expected HasAction('delete') to be true with wildcard action")
	}
}

func TestPolicyValidation(t *testing.T) {
	tests := []struct {
		name      string
		policy    string
		shouldErr bool
		errMsg    string
	}{
		{
			name: "missing policy ID",
			policy: `[{
"name": "Test",
"rules": [{"namespace": "test", "schemaName": "test",
"entityType": "test", "actions": ["read"]}]
}]`,
			shouldErr: true,
			errMsg:    "policy ID is required",
		},
		{
			name: "missing policy name",
			policy: `[{
"id": "test-1",
"rules": [{"namespace": "test", "schemaName": "test",
"entityType": "test", "actions": ["read"]}]
}]`,
			shouldErr: true,
			errMsg:    "policy name is required",
		},
		{
			name: "no rules",
			policy: `[{
"id": "test-1",
"name": "Test",
"rules": []
}]`,
			shouldErr: true,
			errMsg:    "policy must contain at least one rule",
		},
		{
			name: "missing entityType in rule",
			policy: `[{
"id": "test-1",
"name": "Test",
"rules": [{"actions": ["read"]}]
}]`,
			shouldErr: true,
			errMsg:    "entityType is required",
		},
		{
			name: "no actions or relations in rule",
			policy: `[{
"id": "test-1",
"name": "Test",
"rules": [{"namespace": "test", "schemaName": "test",
"entityType": "test"}]
}]`,
			shouldErr: true,
			errMsg:    "rule must define actions, relations, or direct grants",
		},
		{
			name: "missing 'to' in relation",
			policy: `[{
"id": "test-1",
"name": "Test",
"rules": [{
"namespace": "test",
"schemaName": "test",
"entityType": "test",
"relations": [{
"via": "parent",
"actions": ["read"]
}]
}]
}]`,
			shouldErr: true,
			errMsg:    "'to' field is required",
		},
		{
			name: "valid policy",
			policy: `[{
"id": "test-1",
"name": "Test models.Policy",
"description": "A test policy",
"rules": [{
"namespace": "test",
"schemaName": "test",
"entityType": "document",
"actions": ["read", "write"]
}]
}]`,
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			policyFile := filepath.Join(tmpDir, "test.json")

			if err := os.WriteFile(policyFile, []byte(tt.policy), 0644); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			registry := NewPolicyRegistry()
			err := registry.Load(policyFile)

			if tt.shouldErr {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			}
		})
	}
}

func TestPolicyValidation_AllowsRuleSchemaAndEntityWildcards(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "wildcard-rule.json")

	content := `[
{
  "id": "wildcard-rule-policy",
  "name": "Wildcard Rule Policy",
  "description": "Allows wildcard rule matching",
  "rules": [
    {
      "namespace": "iot",
      "schemaName": "*",
      "entityType": "*",
      "actions": ["read"],
      "relations": []
    }
  ]
}
]`

	if err := os.WriteFile(policyFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	registry := NewPolicyRegistry()
	if err := registry.Load(policyFile); err != nil {
		t.Fatalf("Expected wildcard schemaName/entityType to be valid, got error: %v", err)
	}
}

func TestPolicyValidation_RejectsRelationWildcards(t *testing.T) {
	tests := []struct {
		name         string
		relationBody string
		errContains  string
	}{
		{
			name: "reject wildcard to.schemaName",
			relationBody: `"to": {"schemaName": "*", "entityType": "building"},
"via": "organization_id",
"actions": ["read"]`,
			errContains: "to.schemaName",
		},
		{
			name: "reject wildcard to.entityType",
			relationBody: `"to": {"schemaName": "public", "entityType": "*"},
"via": "organization_id",
"actions": ["read"]`,
			errContains: "to.entityType",
		},
		{
			name: "reject wildcard via",
			relationBody: `"to": {"schemaName": "public", "entityType": "building"},
"via": "*",
"actions": ["read"]`,
			errContains: "via",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			policyFile := filepath.Join(tmpDir, "invalid-relation-wildcard.json")

			content := `[
{
  "id": "invalid-rel-wildcard",
  "name": "Invalid Relation Wildcard",
  "rules": [
    {
      "namespace": "iot",
      "schemaName": "public",
      "entityType": "organization",
      "actions": ["read"],
      "relations": [
        {
          ` + tt.relationBody + `
        }
      ]
    }
  ]
}
]`

			if err := os.WriteFile(policyFile, []byte(content), 0644); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			registry := NewPolicyRegistry()
			err := registry.Load(policyFile)
			if err == nil {
				t.Fatalf("Expected wildcard relation field validation error, got nil")
			}

			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("Expected error containing %q, got: %v", tt.errContains, err)
			}
		})
	}
}

func TestPolicyValidation_RejectsRepeatedVertexInRelationPath(t *testing.T) {
	policy := &models.Policy{
		ID:   "policy-cycle",
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

	err := validatePolicyStruct(policy)
	if err == nil {
		t.Fatalf("expected validation error for repeated vertex, got nil")
	}

	if !strings.Contains(err.Error(), "simple") || !strings.Contains(err.Error(), "repeated") {
		t.Fatalf("expected simple-path repeated-vertex error, got: %v", err)
	}
}

func TestPolicyValidation_AllowsRepeatedVertexAcrossDifferentBranches(t *testing.T) {
	policy := &models.Policy{
		ID:   "policy-branches",
		Name: "Policy With Separate Branches",
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
						Via:          "building_id",
						Actions:      []string{"read"},
					},
					{
						ToSchemaName: "public",
						ToEntityType: "building",
						Via:          "backup_building_id",
						Actions:      []string{"read"},
					},
				},
			},
		},
	}

	if err := validatePolicyStruct(policy); err != nil {
		t.Fatalf("expected policy to be valid for separate branches, got: %v", err)
	}
}

func TestPolicyRegistry_GetAll(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policies.json")

	content := `[
{
"id": "policy-1",
"name": "models.Policy 1",
"rules": [
{"namespace": "test",
"schemaName": "test", "entityType": "document", "actions": ["read"]}
]
},
{
"id": "policy-2",
"name": "models.Policy 2",
"rules": [
{"namespace": "test",
"schemaName": "test", "entityType": "folder", "actions": ["read", "write"]}
]
}
]`

	if err := os.WriteFile(policyFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	registry := NewPolicyRegistry()
	if err := registry.Load(policyFile); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	all := registry.GetAll()
	if len(all) != 2 {
		t.Errorf("Expected 2 policies, got %d", len(all))
	}

	// Check that both policies exist
	found := make(map[string]bool)
	for _, policy := range all {
		found[policy.ID] = true
	}

	if !found["policy-1"] {
		t.Error("Expected 'policy-1' to exist")
	}

	if !found["policy-2"] {
		t.Error("Expected 'policy-2' to exist")
	}
}

func TestPolicyRegistry_Load_WithSchemaNameFields(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policies-schema-fields.json")

	content := `[
{
"id": "test-policy-schema-fields",
"name": "Schema fields policy",
"rules": [
{
"namespace": "pki",
"schemaName": "dmsmanager",
"entityType": "dms",
"actions": ["read"],
"relations": [
{
"to": {"schemaName": "devicemanager", "entityType": "device"},
"via": "dms_owner",
"actions": ["read"]
}
]
}
]
}
]`

	if err := os.WriteFile(policyFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	registry := NewPolicyRegistry()
	if err := registry.Load(policyFile); err != nil {
		t.Fatalf("Failed to load policies with schemaName fields: %v", err)
	}

	rule, err := registry.Get("dmsmanager.dms")
	if err != nil {
		t.Fatalf("Failed to get rule by qualified entity type: %v", err)
	}

	if rule.QualifiedEntityType() != "dmsmanager.dms" {
		t.Fatalf("Expected qualified entity type dmsmanager.dms, got %s", rule.QualifiedEntityType())
	}

	if len(rule.Relations) != 1 {
		t.Fatalf("Expected 1 relation, got %d", len(rule.Relations))
	}

	if rule.Relations[0].QualifiedTo() != "devicemanager.device" {
		t.Fatalf("Expected relation target devicemanager.device, got %s", rule.Relations[0].QualifiedTo())
	}
}
