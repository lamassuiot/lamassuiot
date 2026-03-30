package authz

import (
	"strings"
	"testing"

	"github.com/lamassuiot/authz/pkg/models"
)

func TestFilterGenerator_DirectOwnership(t *testing.T) {
	// Setup registries
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)

	// Test direct device ownership - policy has directGrants ["device-1", "device-4"]
	result, err := fg.GenerateListFilter("read", "public", "device")
	if err != nil {
		t.Fatalf("GenerateListFilter failed: %v", err)
	}

	whereClause := strings.Join(result.Conditions, " OR ")

	if whereClause == "1 = 0" {
		t.Error("Expected filter to allow access, got impossible condition")
	}

	// Should contain direct match for device ID
	if !strings.Contains(whereClause, "id IN") {
		t.Errorf("Expected direct ID filter, got: %s", whereClause)
	}

	if !strings.Contains(whereClause, "'device-1'") {
		t.Errorf("Expected device ID 'device-1' in inlined SQL, got: %s", whereClause)
	}
}

func TestFilterGenerator_CascadingOwnership(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)

	// Test cascading: policies should define organization directGrants to cascade to devices
	result, err := fg.GenerateListFilter("read", "public", "device")
	if err != nil {
		t.Fatalf("GenerateListFilter failed: %v", err)
	}

	whereClause := strings.Join(result.Conditions, " OR ")

	if whereClause == "1 = 0" {
		t.Error("Expected filter to allow cascading access")
	}

	// Should have JOINs for cascading access
	if len(result.Joins) == 0 {
		t.Error("Expected JOINs for cascading access")
	}

	// Should have inlined org ID for cascading ownership
	if !strings.Contains(whereClause, "'org-1'") {
		t.Error("Expected inlined org ID for cascading ownership")
	}

	t.Logf("Generated WHERE clause: %s", whereClause)
	t.Logf("Generated JOINs: %v", result.Joins)
}

func TestFilterGenerator_BuildingManager(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)

	// Building directGrants (if defined in policy)
	result, err := fg.GenerateListFilter("read", "public", "building")
	if err != nil {
		t.Fatalf("GenerateListFilter failed: %v", err)
	}

	whereClause := strings.Join(result.Conditions, " OR ")

	if whereClause == "1 = 0" {
		t.Error("Expected filter to allow access to buildings")
	}

	// Should contain direct ID match
	if !strings.Contains(whereClause, "id IN") {
		t.Errorf("Expected direct ID filter, got: %s", whereClause)
	}

	t.Logf("Building filter: %s", whereClause)
}

func TestFilterGenerator_CheckFilter(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)

	// Check specific device access
	result, err := fg.GenerateCheckFilter("read", "public", "device", map[string]string{"device_id": "device-1"})
	if err != nil {
		t.Fatalf("GenerateCheckFilter failed: %v", err)
	}

	// Check filter should have 2 conditions:
	// 1. Access conditions wrapped in parentheses (access_cond1 OR access_cond2 OR ...)
	// 2. Entity ID check
	if len(result.Conditions) != 2 {
		t.Errorf("Expected 2 conditions (access + entity ID), got %d", len(result.Conditions))
	}

	// First condition should be wrapped in parentheses (access conditions)
	if !strings.HasPrefix(result.Conditions[0], "(") || !strings.HasSuffix(result.Conditions[0], ")") {
		t.Errorf("Expected access conditions to be wrapped in parentheses, got: %s", result.Conditions[0])
	}

	// Second condition should be the entity ID check
	if !strings.Contains(result.Conditions[1], "device_id = 'device-1'") {
		t.Errorf("Expected device_id check in second condition, got: %s", result.Conditions[1])
	}

	// When joined with AND, should produce: (access conditions) AND id = ?
	whereClause := strings.Join(result.Conditions, " AND ")
	t.Logf("Check filter: %s", whereClause)
}

func TestFilterGenerator_WildcardRuleSchemaAndEntity(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	policy := &models.Policy{
		ID:          "wildcard-rule-filter",
		Name:        "Wildcard Rule Filter",
		Description: "Wildcard schema/entity should match target schema",
		Rules: []*models.Rule{
			{
				Namespace:    "iot",
				SchemaName:   "*",
				EntityType:   "*",
				Actions:      []string{"read"},
				DirectGrants: []string{"device-1"},
			},
		},
	}

	if err := policies.AddPolicy(policy); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)
	result, err := fg.GenerateListFilter("read", "public", "device")
	if err != nil {
		t.Fatalf("GenerateListFilter failed: %v", err)
	}

	whereClause := strings.Join(result.Conditions, " OR ")
	if !strings.Contains(whereClause, "'device-1'") {
		t.Fatalf("Expected wildcard rule to contribute direct grant filter, got: %s", whereClause)
	}
}

func TestFilterGenerator_WildcardAction_DirectGrant(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	policy := &models.Policy{
		ID:          "wildcard-action-direct-filter",
		Name:        "Wildcard Action Direct Filter",
		Description: "Wildcard action should match read for direct grants",
		Rules: []*models.Rule{
			{
				Namespace:    "iot",
				SchemaName:   "public",
				EntityType:   "device",
				Actions:      []string{"*"},
				DirectGrants: []string{"*"},
			},
		},
	}

	if err := policies.AddPolicy(policy); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)
	result, err := fg.GenerateListFilter("read", "public", "device")
	if err != nil {
		t.Fatalf("GenerateListFilter failed: %v", err)
	}

	whereClause := strings.Join(result.Conditions, " OR ")
	if whereClause != "1 = 1" {
		t.Fatalf("Expected wildcard action + wildcard grant to allow all entities, got: %s", whereClause)
	}
}

func TestFilterGenerator_WildcardAction_RelationCascade(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	policy := &models.Policy{
		ID:          "wildcard-action-relation-filter",
		Name:        "Wildcard Action Relation Filter",
		Description: "Wildcard relation action should allow cascade",
		Rules: []*models.Rule{
			{
				Namespace:  "iot",
				SchemaName: "public",
				EntityType: "building",
				Actions:    []string{"read"},
				Relations: []models.RelationRule{
					{
						ToSchemaName: "public",
						ToEntityType: "gateway",
						Via:          "building_id",
						Actions:      []string{"*"},
					},
				},
				DirectGrants: []string{"building-1"},
			},
		},
	}

	if err := policies.AddPolicy(policy); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)
	result, err := fg.GenerateListFilter("read", "public", "gateway")
	if err != nil {
		t.Fatalf("GenerateListFilter failed: %v", err)
	}

	whereClause := strings.Join(result.Conditions, " OR ")
	if whereClause == "1 = 0" {
		t.Fatalf("Expected wildcard relation action to enable cascade, got: %s", whereClause)
	}

	if len(result.Joins) == 0 {
		t.Fatalf("Expected cascade JOINs for wildcard relation action, got none")
	}
}

func TestFilterGenerator_NoAccess(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)

	// Test with an action that doesn't exist in any policy for organization
	// All policies for organization have read, write, delete - but not "execute"
	result, err := fg.GenerateListFilter("execute", "public", "organization")
	if err != nil {
		t.Fatalf("GenerateListFilter failed: %v", err)
	}

	whereClause := strings.Join(result.Conditions, " OR ")

	// No policies support this action, so should get impossible condition
	if whereClause != "1 = 0" {
		t.Errorf("Expected impossible condition for unsupported action, got: %s", whereClause)
	}

	t.Logf("No access filter: %s", whereClause)
}

func TestFilterGenerator_NoAccessCheckFilter(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)

	// Test check filter with an action that doesn't exist in any policy
	// This should return just "1 = 0" without adding the entity ID check
	result, err := fg.GenerateCheckFilter("execute", "public", "device", map[string]string{"device_id": "device-1"})
	if err != nil {
		t.Fatalf("GenerateCheckFilter failed: %v", err)
	}

	// Should have only one condition: "1 = 0"
	if len(result.Conditions) != 1 {
		t.Errorf("Expected 1 condition for no access, got %d: %v", len(result.Conditions), result.Conditions)
	}

	if result.Conditions[0] != "1 = 0" {
		t.Errorf("Expected '1 = 0' for no access, got: %s", result.Conditions[0])
	}

	t.Logf("No access check filter: %s", strings.Join(result.Conditions, " AND "))
}

func TestFilterGenerator_MultipleActions(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)

	// Test different actions - user owns device "device-001"
	actions := []string{"read", "write", "control", "delete"}
	for _, action := range actions {
		result, err := fg.GenerateListFilter(action, "public", "device")
		if err != nil {
			t.Errorf("GenerateListFilter failed for action %s: %v", action, err)
			continue
		}

		whereClause := strings.Join(result.Conditions, " OR ")

		if whereClause == "" {
			t.Errorf("Empty filter for action %s", action)
		}

		t.Logf("Action %s: %s", action, whereClause)
	}
}

func TestFilterGenerator_InvalidEntity(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)

	// Test with non-existent entity
	_, err := fg.GenerateListFilter("read", "public", "nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent entity")
	}
}

func TestFilterGenerator_Gateway(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)

	// Gateway access (depends on policy directGrants)
	result, err := fg.GenerateListFilter("read", "public", "gateway")
	if err != nil {
		t.Fatalf("GenerateListFilter failed: %v", err)
	}

	whereClause := strings.Join(result.Conditions, " OR ")

	if whereClause == "1 = 0" {
		t.Error("Expected filter to allow gateway access")
	}

	// Should have JOINs for building relationship
	if len(result.Joins) == 0 {
		t.Error("Expected JOINs for gateway access through building")
	}

	t.Logf("Gateway filter: %s with %d joins", whereClause, len(result.Joins))
}

func TestFilterGenerator_OrganizationAccess(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)

	// Organization access (depends on policy directGrants)
	result, err := fg.GenerateListFilter("read", "public", "organization")
	if err != nil {
		t.Fatalf("GenerateListFilter failed: %v", err)
	}

	whereClause := strings.Join(result.Conditions, " OR ")

	if whereClause == "1 = 0" {
		t.Error("Expected filter to allow organization access")
	}

	// Should have direct ID check using IN clause
	if !strings.Contains(whereClause, "id IN") {
		t.Errorf("Expected id IN filter, got: %s", whereClause)
	}

	if !strings.Contains(whereClause, "'org-1'") {
		t.Error("Expected inlined organization ID")
	}

	t.Logf("Organization filter: %s", whereClause)
}

func TestFilterGenerator_ControlDevice(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)

	// Test control action on devices
	result, err := fg.GenerateListFilter("control", "public", "device")
	if err != nil {
		t.Fatalf("GenerateListFilter failed for control action: %v", err)
	}

	whereClause := strings.Join(result.Conditions, " OR ")

	if whereClause == "1 = 0" {
		t.Error("Expected filter to allow control access to devices")
	}

	if whereClause == "" {
		t.Error("Expected non-empty WHERE clause for control action")
	}

	// Should have some access condition (direct or cascading)
	hasDirectAccess := strings.Contains(whereClause, "id IN")
	hasCascadingAccess := len(result.Joins) > 0

	if !hasDirectAccess && !hasCascadingAccess {
		t.Errorf("Expected either direct or cascading access condition, got: %s", whereClause)
	}

	if !strings.Contains(whereClause, "'") {
		t.Error("Expected inlined literal values for control filter")
	}

	t.Logf("Control device filter: %s", whereClause)

	// Also test GenerateCheckFilter for a specific device control
	checkResult, err := fg.GenerateCheckFilter("control", "public", "device", map[string]string{"device_id": "device-1"})
	if err != nil {
		t.Fatalf("GenerateCheckFilter failed for control action: %v", err)
	}

	checkWhereClause := strings.Join(checkResult.Conditions, " OR ")

	if !strings.Contains(checkWhereClause, "device_id = 'device-1'") {
		t.Errorf("Expected id check in control filter, got: %s", checkWhereClause)
	}

	t.Logf("Control check filter: %s", checkWhereClause)
}

func TestFilterResult_FullSQL(t *testing.T) {
	// Test that FullSQL field is populated correctly
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)

	// Test GenerateListFilter
	listResult, err := fg.GenerateListFilter("read", "public", "device")
	if err != nil {
		t.Fatalf("GenerateListFilter failed: %v", err)
	}

	// FullSQL should be empty for list filters as they don't use buildPathFilter
	// (they use direct conditions, not path-based filters)
	t.Logf("List filter FullSQL (should be empty): %s", listResult.FullSQL)

	// Test GenerateCheckFilter - this also doesn't directly use buildPathFilter
	checkResult, err := fg.GenerateCheckFilter("read", "public", "device", map[string]string{"device_id": "device-1"})
	if err != nil {
		t.Fatalf("GenerateCheckFilter failed: %v", err)
	}

	t.Logf("Check filter FullSQL (should be empty): %s", checkResult.FullSQL)

	// Note: FullSQL is populated in buildPathFilter/buildPathFilterWildcard
	// which are called internally for cascading access paths
	// To test this, we'd need a policy that creates cascading paths
}

func TestBuildPathFilterWildcard_SingleHop(t *testing.T) {
	// One-hop wildcard: dms (directGrants=["*"]) → device, listing devices.
	// Condition must use the dms alias (j0_0) with the dms primary key.
	schemas := NewSchemaRegistry()
	if err := schemas.Load("../../examples/iot/schemas.pki-v2.json", "pki"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	fg := NewFilterGenerator(schemas, NewPolicyRegistry())

	path := []*GraphEdge{
		{From: "dmsmanager.dms", To: "devicemanager.device", ForeignKey: "dms_owner"},
	}

	result, err := fg.buildPathFilterWildcard("dmsmanager.dms", path, 0)
	if err != nil {
		t.Fatalf("buildPathFilterWildcard failed: %v", err)
	}

	if len(result.Joins) != 1 {
		t.Fatalf("expected 1 join, got %d: %v", len(result.Joins), result.Joins)
	}
	if len(result.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d: %v", len(result.Conditions), result.Conditions)
	}

	// j0_0 is the alias for the single join, which is the dms table (owned entity).
	if result.Conditions[0] != "j0_0.id IS NOT NULL" {
		t.Errorf("expected condition 'j0_0.id IS NOT NULL', got: %s", result.Conditions[0])
	}
}

func TestBuildPathFilterWildcard_TwoHop(t *testing.T) {
	// Two-hop wildcard: dms (directGrants=["*"]) → device → certificate, listing certificates.
	// This is the exact scenario from the bug report.
	//
	// Before the fix, the condition was `j0_0.serial_number IS NOT NULL`:
	//   - j0_0 is the devicemanager.devices alias
	//   - serial_number is the primary key of ca.certificates — wrong table, wrong column
	//
	// After the fix the condition must be `j0_1.id IS NOT NULL`:
	//   - j0_1 is the last alias in the reversed traversal, which maps to dmsmanager.dms
	//   - id is the primary key of dmsmanager.dms
	schemas := NewSchemaRegistry()
	if err := schemas.Load("../../examples/iot/schemas.pki-v2.json", "pki"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	fg := NewFilterGenerator(schemas, NewPolicyRegistry())

	path := []*GraphEdge{
		{From: "dmsmanager.dms", To: "devicemanager.device", ForeignKey: "dms_owner"},
		{From: "devicemanager.device", To: "ca.certificate", ForeignKey: "subject_common_name"},
	}

	result, err := fg.buildPathFilterWildcard("dmsmanager.dms", path, 0)
	if err != nil {
		t.Fatalf("buildPathFilterWildcard failed: %v", err)
	}

	if len(result.Joins) != 2 {
		t.Fatalf("expected 2 joins, got %d: %v", len(result.Joins), result.Joins)
	}
	if len(result.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d: %v", len(result.Conditions), result.Conditions)
	}

	// j0_0 = devicemanager.devices alias, j0_1 = dmsmanager.dms alias (owned entity).
	// The condition must be on j0_1 (dms), not j0_0 (device).
	if result.Conditions[0] != "j0_1.id IS NOT NULL" {
		t.Errorf("expected condition 'j0_1.id IS NOT NULL', got: %s", result.Conditions[0])
	}
	// Explicit regression: the old bug produced j0_0.serial_number IS NOT NULL.
	if result.Conditions[0] == "j0_0.serial_number IS NOT NULL" {
		t.Error("regression: condition must not use certificate primary key on device alias")
	}
}

func TestGenerateListFilter_WildcardDirectGrantCascadesToCertificate(t *testing.T) {
	// End-to-end test matching the bug-report policy:
	// A principal has a rule on dmsmanager.dms with directGrants=["*"].
	// The policy cascades dms → device (via dms_owner) → certificate (via subject_common_name).
	// GenerateListFilter for "read" on ca.certificate must produce two JOINs and a WHERE
	// condition that references the dms alias with the dms primary key.
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.pki-v2.json", "pki"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	policy := &models.Policy{
		ID:   "test-dms-wildcard-cascade",
		Name: "DMS Wildcard Cascade",
		Rules: []*models.Rule{
			{
				Namespace:  "pki",
				SchemaName: "dmsmanager",
				EntityType: "dms",
				Actions:    []string{"read"},
				Relations: []models.RelationRule{
					{
						ToSchemaName: "devicemanager",
						ToEntityType: "device",
						To:           "devicemanager.device",
						Via:          "dms_owner",
						Actions:      []string{"read"},
						Relations: []models.RelationRule{
							{
								ToSchemaName: "ca",
								ToEntityType: "certificate",
								To:           "ca.certificate",
								Via:          "subject_common_name",
								Actions:      []string{"read"},
							},
						},
					},
				},
				DirectGrants: []string{"*"},
			},
		},
	}
	if err := policies.AddPolicy(policy); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)
	result, err := fg.GenerateListFilter("read", "ca", "certificate")
	if err != nil {
		t.Fatalf("GenerateListFilter failed: %v", err)
	}

	if len(result.Joins) != 2 {
		t.Fatalf("expected 2 JOINs for dms→device→certificate path, got %d: %v", len(result.Joins), result.Joins)
	}
	if len(result.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d: %v", len(result.Conditions), result.Conditions)
	}

	// The device join: certificates.subject_common_name → devices.id
	if !strings.Contains(result.Joins[0], "devicemanager.devices") {
		t.Errorf("expected first JOIN to reference devicemanager.devices, got: %s", result.Joins[0])
	}
	// The dms join: devices.dms_owner → dms.id
	if !strings.Contains(result.Joins[1], "dmsmanager.dms") {
		t.Errorf("expected second JOIN to reference dmsmanager.dms, got: %s", result.Joins[1])
	}

	// The WHERE condition must use the dms alias (j0_1) with dms primary key (id).
	// Before the fix this was j0_0.serial_number (certificate PK on device alias).
	if result.Conditions[0] != "j0_1.id IS NOT NULL" {
		t.Errorf("expected 'j0_1.id IS NOT NULL', got: %s", result.Conditions[0])
	}

	t.Logf("Joins: %v", result.Joins)
	t.Logf("Conditions: %v", result.Conditions)
}

func TestFilterGenerator_ColumnFilter_SingleCondition(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	policy := &models.Policy{
		ID:   "col-filter-single",
		Name: "Column Filter Single",
		Rules: []*models.Rule{
			{
				Namespace:  "iot",
				SchemaName: "public",
				EntityType: "device",
				Actions:    []string{"read"},
				ColumnFilters: []models.ColumnFilter{
					{Column: "status", Operator: "eq", Value: "active"},
				},
			},
		},
	}
	if err := policies.AddPolicy(policy); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)
	result, err := fg.GenerateListFilter("read", "public", "device")
	if err != nil {
		t.Fatalf("GenerateListFilter failed: %v", err)
	}

	whereClause := strings.Join(result.Conditions, " OR ")
	if !strings.Contains(whereClause, "iot_devices.status = 'active'") {
		t.Errorf("Expected column filter condition, got: %s", whereClause)
	}
	t.Logf("Column filter SQL: %s", whereClause)
}

func TestFilterGenerator_ColumnFilter_MultipleConditionsANDed(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	policy := &models.Policy{
		ID:   "col-filter-multi",
		Name: "Column Filter Multi",
		Rules: []*models.Rule{
			{
				Namespace:  "iot",
				SchemaName: "public",
				EntityType: "device",
				Actions:    []string{"read"},
				ColumnFilters: []models.ColumnFilter{
					{Column: "status", Operator: "eq", Value: "active"},
					{Column: "tenant_id", Operator: "eq", Value: "acme"},
				},
			},
		},
	}
	if err := policies.AddPolicy(policy); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)
	result, err := fg.GenerateListFilter("read", "public", "device")
	if err != nil {
		t.Fatalf("GenerateListFilter failed: %v", err)
	}

	// Multiple filters in one rule must be ANDed together in a single condition entry
	if len(result.Conditions) != 1 {
		t.Errorf("Expected 1 combined condition, got %d: %v", len(result.Conditions), result.Conditions)
	}
	cond := result.Conditions[0]
	if !strings.Contains(cond, "iot_devices.status = 'active'") {
		t.Errorf("Expected status condition in: %s", cond)
	}
	if !strings.Contains(cond, "iot_devices.tenant_id = 'acme'") {
		t.Errorf("Expected tenant_id condition in: %s", cond)
	}
	if !strings.Contains(cond, " AND ") {
		t.Errorf("Expected AND between conditions, got: %s", cond)
	}
	t.Logf("Multi column filter SQL: %s", cond)
}

func TestFilterGenerator_ColumnFilter_BoolValue(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	policy := &models.Policy{
		ID:   "col-filter-bool",
		Name: "Column Filter Bool",
		Rules: []*models.Rule{
			{
				Namespace:  "iot",
				SchemaName: "public",
				EntityType: "device",
				Actions:    []string{"read"},
				ColumnFilters: []models.ColumnFilter{
					{Column: "active", Operator: "eq", Value: true},
				},
			},
		},
	}
	if err := policies.AddPolicy(policy); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)
	result, err := fg.GenerateListFilter("read", "public", "device")
	if err != nil {
		t.Fatalf("GenerateListFilter failed: %v", err)
	}

	whereClause := strings.Join(result.Conditions, " OR ")
	if !strings.Contains(whereClause, "iot_devices.active = true") {
		t.Errorf("Expected boolean column filter condition, got: %s", whereClause)
	}
}

func TestFilterGenerator_ColumnFilter_InOperator(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	policy := &models.Policy{
		ID:   "col-filter-in",
		Name: "Column Filter IN",
		Rules: []*models.Rule{
			{
				Namespace:  "iot",
				SchemaName: "public",
				EntityType: "device",
				Actions:    []string{"read"},
				ColumnFilters: []models.ColumnFilter{
					{Column: "status", Operator: "in", Value: []interface{}{"active", "provisioning"}},
				},
			},
		},
	}
	if err := policies.AddPolicy(policy); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)
	result, err := fg.GenerateListFilter("read", "public", "device")
	if err != nil {
		t.Fatalf("GenerateListFilter failed: %v", err)
	}

	whereClause := strings.Join(result.Conditions, " OR ")
	if !strings.Contains(whereClause, "iot_devices.status IN ('active', 'provisioning')") {
		t.Errorf("Expected IN condition, got: %s", whereClause)
	}
}

func TestFilterGenerator_ColumnFilter_NonFilterableColumnReturnsError(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	policy := &models.Policy{
		ID:   "col-filter-invalid",
		Name: "Column Filter Invalid",
		Rules: []*models.Rule{
			{
				Namespace:  "iot",
				SchemaName: "public",
				EntityType: "device",
				Actions:    []string{"read"},
				ColumnFilters: []models.ColumnFilter{
					{Column: "undeclared_col", Operator: "eq", Value: "foo"},
				},
			},
		},
	}
	if err := policies.AddPolicy(policy); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)
	_, err := fg.GenerateListFilter("read", "public", "device")
	if err == nil {
		t.Error("Expected error for undeclared filterable column, got nil")
	}
	if !strings.Contains(err.Error(), "undeclared_col") {
		t.Errorf("Expected error to mention the column name, got: %v", err)
	}
}

func TestFilterGenerator_ColumnFilter_TypeMatchesSchema(t *testing.T) {
	// When filter.Type matches the schema's declared type the filter is applied normally.
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	policy := &models.Policy{
		ID:   "col-type-match",
		Name: "Column Type Match",
		Rules: []*models.Rule{
			{
				Namespace:  "iot",
				SchemaName: "public",
				EntityType: "device",
				Actions:    []string{"read"},
				ColumnFilters: []models.ColumnFilter{
					{Column: "status", Type: "string", Operator: "eq", Value: "active"},
				},
			},
		},
	}
	if err := policies.AddPolicy(policy); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)
	result, err := fg.GenerateListFilter("read", "public", "device")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	whereClause := strings.Join(result.Conditions, " OR ")
	if !strings.Contains(whereClause, "iot_devices.status = 'active'") {
		t.Errorf("Expected condition with correct column ref, got: %s", whereClause)
	}
}

func TestFilterGenerator_ColumnFilter_TypeMismatchReturnsError(t *testing.T) {
	// When filter.Type contradicts the schema's declared type an error is returned.
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	policy := &models.Policy{
		ID:   "col-type-mismatch",
		Name: "Column Type Mismatch",
		Rules: []*models.Rule{
			{
				Namespace:  "iot",
				SchemaName: "public",
				EntityType: "device",
				Actions:    []string{"read"},
				ColumnFilters: []models.ColumnFilter{
					// "status" is declared as "string" in the schema; "int" is wrong.
					{Column: "status", Type: "int", Operator: "eq", Value: 1},
				},
			},
		},
	}
	if err := policies.AddPolicy(policy); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)
	_, err := fg.GenerateListFilter("read", "public", "device")
	if err == nil {
		t.Fatal("Expected type mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "status") {
		t.Errorf("Expected error to mention the column name, got: %v", err)
	}
	if !strings.Contains(err.Error(), "int") || !strings.Contains(err.Error(), "string") {
		t.Errorf("Expected error to mention both declared and schema types, got: %v", err)
	}
}

func TestFilterGenerator_ColumnFilter_ActionNotMatched(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	// Rule only grants "read" via column filter
	policy := &models.Policy{
		ID:   "col-filter-action-mismatch",
		Name: "Column Filter Action Mismatch",
		Rules: []*models.Rule{
			{
				Namespace:  "iot",
				SchemaName: "public",
				EntityType: "device",
				Actions:    []string{"read"},
				ColumnFilters: []models.ColumnFilter{
					{Column: "status", Operator: "eq", Value: "active"},
				},
			},
		},
	}
	if err := policies.AddPolicy(policy); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)
	// Requesting "delete" — not granted by this rule
	result, err := fg.GenerateListFilter("delete", "public", "device")
	if err != nil {
		t.Fatalf("GenerateListFilter failed: %v", err)
	}

	whereClause := strings.Join(result.Conditions, " OR ")
	if whereClause != "1 = 0" {
		t.Errorf("Expected no access (1 = 0) for unmatched action, got: %s", whereClause)
	}
}

func TestPolicyValidation_ColumnFilter_InvalidOperator(t *testing.T) {
	policies := NewPolicyRegistry()

	policy := &models.Policy{
		ID:   "bad-operator",
		Name: "Bad Operator",
		Rules: []*models.Rule{
			{
				Namespace:  "iot",
				SchemaName: "public",
				EntityType: "device",
				Actions:    []string{"read"},
				ColumnFilters: []models.ColumnFilter{
					{Column: "status", Operator: "contains", Value: "foo"},
				},
			},
		},
	}
	err := policies.AddPolicy(policy)
	if err == nil {
		t.Error("Expected validation error for invalid operator, got nil")
	}
}

func TestGenerateListFilter_SpecificDeviceIDRevokeCascadesToCertificate(t *testing.T) {
	// Regression test for the policy scenario reported in the bug:
	// Rule 1: dmsmanager.dms with directGrants=["sample-dms-01"], cascades read/ui to certs.
	// Rule 2: devicemanager.device with directGrants=["device-007"], cascades
	//         status-update/revoke to ca.certificate via subject_common_name.
	// GenerateListFilter("status-update/revoke", "ca", "certificate") must produce a
	// single-hop JOIN condition on device alias (j0_0.id = 'device-007'), NOT "1 = 0".
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.pki-v2.json", "pki"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	policy := &models.Policy{
		ID:   "device-007-revoke-policy",
		Name: "Device-007 revoke policy",
		Rules: []*models.Rule{
			{
				Namespace:  "pki",
				SchemaName: "dmsmanager",
				EntityType: "dms",
				Actions:    []string{"read", "create", "ui"},
				Relations: []models.RelationRule{
					{
						ToSchemaName: "devicemanager",
						ToEntityType: "device",
						To:           "devicemanager.device",
						Via:          "dms_owner",
						Actions:      []string{"read", "decomission", "ui"},
						Relations: []models.RelationRule{
							{
								ToSchemaName: "ca",
								ToEntityType: "certificate",
								To:           "ca.certificate",
								Via:          "subject_common_name",
								// read/ui only — status-update/revoke intentionally absent here
								Actions: []string{"read", "ui"},
							},
						},
					},
				},
				DirectGrants: []string{"sample-dms-01"},
			},
			{
				Namespace:  "pki",
				SchemaName: "devicemanager",
				EntityType: "device",
				Actions:    []string{"read"},
				Relations: []models.RelationRule{
					{
						ToSchemaName: "ca",
						ToEntityType: "certificate",
						To:           "ca.certificate",
						Via:          "subject_common_name",
						Actions:      []string{"status-update/revoke", "read"},
					},
				},
				DirectGrants: []string{"device-007"},
			},
		},
	}
	if err := policies.AddPolicy(policy); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)
	result, err := fg.GenerateListFilter("status-update/revoke", "ca", "certificate")
	if err != nil {
		t.Fatalf("GenerateListFilter failed: %v", err)
	}

	t.Logf("Joins: %v", result.Joins)
	t.Logf("Conditions: %v", result.Conditions)

	// Must not be a deny-all — Rule 2 provides a valid revoke path via device-007.
	if len(result.Conditions) == 1 && result.Conditions[0] == "1 = 0" {
		t.Fatal("expected revoke access via device-007 cascade, got deny-all (1 = 0)")
	}

	// Exactly one JOIN (device table) — the dms rule does NOT grant revoke so its
	// two-hop path must be excluded.
	if len(result.Joins) != 1 {
		t.Fatalf("expected 1 JOIN (device table only), got %d: %v", len(result.Joins), result.Joins)
	}
	if !strings.Contains(result.Joins[0], "devicemanager.devices") {
		t.Errorf("expected JOIN to reference devicemanager.devices, got: %s", result.Joins[0])
	}

	// The WHERE condition must target the device alias with device-007's ID.
	if result.Conditions[0] != "j0_0.id = 'device-007'" {
		t.Errorf("expected condition \"j0_0.id = 'device-007'\", got: %s", result.Conditions[0])
	}
}

func TestBuildPathFilter_UsesOwnedEntityAliasForMultiHopPath(t *testing.T) {
	schemas := NewSchemaRegistry()
	policies := NewPolicyRegistry()

	if err := schemas.Load("../../examples/iot/schemas.pki-v2.json", "pki"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)

	path := []*GraphEdge{
		{From: "dmsmanager.dms", To: "devicemanager.device", ForeignKey: "dms_owner"},
		{From: "devicemanager.device", To: "ca.certificate", ForeignKey: "subject_common_name"},
	}

	result, err := fg.buildPathFilter("dmsmanager.dms", "sample-dms-01", path, 0)
	if err != nil {
		t.Fatalf("buildPathFilter failed: %v", err)
	}

	whereClause := strings.Join(result.Conditions, " AND ")

	if !strings.Contains(whereClause, "j0_1.id = 'sample-dms-01'") {
		t.Fatalf("expected owned entity condition on alias j0_1, got: %s", whereClause)
	}

	if strings.Contains(whereClause, "j0_0.id = 'sample-dms-01'") {
		t.Fatalf("expected condition not to use intermediate alias j0_0, got: %s", whereClause)
	}
}
