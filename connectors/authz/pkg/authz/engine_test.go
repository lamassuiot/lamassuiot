package authz

import (
	"strings"
	"testing"

	"github.com/lamassuiot/authz/pkg/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Create IoT tables
	if err := db.Exec(`
CREATE TABLE organizations (
id VARCHAR(255) PRIMARY KEY,
name VARCHAR(255) NOT NULL,
owner_id VARCHAR(255)
)
`).Error; err != nil {
		t.Fatalf("Failed to create organizations table: %v", err)
	}

	if err := db.Exec(`
CREATE TABLE buildings (
id VARCHAR(255) PRIMARY KEY,
name VARCHAR(255) NOT NULL,
organization_id VARCHAR(255),
manager_id VARCHAR(255)
)
`).Error; err != nil {
		t.Fatalf("Failed to create buildings table: %v", err)
	}

	if err := db.Exec(`
CREATE TABLE iot_gateways (
id VARCHAR(255) PRIMARY KEY,
name VARCHAR(255) NOT NULL,
building_id VARCHAR(255)
)
`).Error; err != nil {
		t.Fatalf("Failed to create gateways table: %v", err)
	}

	if err := db.Exec(`
CREATE TABLE iot_devices (
device_id VARCHAR(255) PRIMARY KEY,
name VARCHAR(255) NOT NULL,
gateway_id VARCHAR(255),
assigned_technician_id VARCHAR(255)
)
`).Error; err != nil {
		t.Fatalf("Failed to create devices table: %v", err)
	}

	// Insert test data
	if err := db.Exec(`
INSERT INTO organizations (id, name, owner_id) VALUES
('org-1', 'ACME Corp', 'user-owner'),
('org-2', 'Tech Inc', 'user-other-owner')
`).Error; err != nil {
		t.Fatalf("Failed to insert organizations: %v", err)
	}

	if err := db.Exec(`
INSERT INTO buildings (id, name, organization_id, manager_id) VALUES
('building-1', 'HQ Building', 'org-1', 'user-manager'),
('building-2', 'Factory', 'org-1', 'user-other-manager'),
('building-3', 'Tech Campus', 'org-2', 'user-other-owner')
`).Error; err != nil {
		t.Fatalf("Failed to insert buildings: %v", err)
	}

	if err := db.Exec(`
INSERT INTO iot_gateways (id, name, building_id) VALUES
('gateway-1', 'HQ Gateway 1', 'building-1'),
('gateway-2', 'HQ Gateway 2', 'building-1'),
('gateway-3', 'Factory Gateway', 'building-2')
`).Error; err != nil {
		t.Fatalf("Failed to insert gateways: %v", err)
	}

	if err := db.Exec(`
INSERT INTO iot_devices (device_id, name, gateway_id, assigned_technician_id) VALUES
('device-1', 'Sensor A', 'gateway-1', 'user-tech'),
('device-2', 'Sensor B', 'gateway-1', 'user-tech'),
('device-3', 'Sensor C', 'gateway-2', 'user-other-tech'),
('device-4', 'Actuator D', 'gateway-3', 'user-tech')
`).Error; err != nil {
		t.Fatalf("Failed to insert devices: %v", err)
	}

	return db
}

func TestNewEngine(t *testing.T) {
	db := setupTestDB(t)

	dbs := map[string]*gorm.DB{
		"iot_schema": db,
	}
	schemaPaths := map[string]string{
		"iot_schema": "../../examples/iot/schemas.test.json",
	}

	engine, err := NewEngine(dbs, schemaPaths)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	if engine == nil {
		t.Fatal("Engine is nil")
	}

	if engine.dbs == nil {
		t.Error("Engine databases map is nil")
	}

	if engine.schemas == nil {
		t.Error("Engine schemas is nil")
	}

	// Verify schemas loaded
	schemas := engine.GetSchemas().GetAll()
	if len(schemas) != 4 {
		t.Errorf("Expected 4 schemas, got %d", len(schemas))
	}
}

func TestEngine_Authorize_NonExistentEntity(t *testing.T) {
	db := setupTestDB(t)
	dbs := map[string]*gorm.DB{
		"iot_schema": db,
	}
	schemaPaths := map[string]string{
		"iot_schema": "../../examples/iot/schemas.test.json",
	}
	engine, err := NewEngine(dbs, schemaPaths)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Load policies
	policies := NewPolicyRegistry()
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	// Non-existent device should return false
	allowed, err := engine.Authorize(policies, "iot_schema", "public", "read", "device", map[string]string{"device_id": "device-999"})
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}
	if allowed {
		t.Error("Expected no access to non-existent device")
	}
}

func TestEngine_GetListFilter(t *testing.T) {
	db := setupTestDB(t)
	dbs := map[string]*gorm.DB{
		"iot": db,
	}
	schemaPaths := map[string]string{
		"iot": "../../examples/iot/schemas.json",
	}
	engine, err := NewEngine(dbs, schemaPaths)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Load policies
	policies := NewPolicyRegistry()
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	// Get list filter based on policy directGrants
	filterSQL, err := engine.GetListFilter(policies, "iot", "public", "device")
	if err != nil {
		t.Fatalf("GetListFilter failed: %v", err)
	}

	if filterSQL == "" {
		t.Fatal("Filter SQL is empty")
	}

	// Should have a WHERE clause for directGrants
	if !strings.Contains(filterSQL, "WHERE") {
		t.Error("Filter SQL should contain WHERE clause")
	}

	// Should have conditions for directGrants (not impossible filter)
	if strings.Contains(filterSQL, "1 = 0") {
		t.Error("Filter should not be impossible when directGrants exist")
	}

	t.Logf("Filter SQL: %s", filterSQL)
}

func TestEngine_InvalidEntityType(t *testing.T) {
	db := setupTestDB(t)
	dbs := map[string]*gorm.DB{
		"iot_schema": db,
	}
	schemaPaths := map[string]string{
		"iot_schema": "../../examples/iot/schemas.test.json",
	}
	engine, err := NewEngine(dbs, schemaPaths)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Load policies
	policies := NewPolicyRegistry()
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	// Try to authorize non-existent entity type
	_, err = engine.Authorize(policies, "iot_schema", "public", "read", "nonexistent", map[string]string{"id": "123"})
	if err == nil {
		t.Error("Expected error for non-existent entity type")
	}

	// Try to get filter for non-existent entity type
	_, err = engine.GetListFilter(policies, "iot_schema", "public", "nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent entity type")
	}
}

func TestEngine_GlobalAction_EmptyDirectGrants(t *testing.T) {
	db := setupTestDB(t)
	dbs := map[string]*gorm.DB{
		"iot_schema": db,
	}
	schemaPaths := map[string]string{
		"iot_schema": "../../examples/iot/schemas.test.json",
	}
	engine, err := NewEngine(dbs, schemaPaths)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Create a policy with a global action but empty directGrants
	policies := NewPolicyRegistry()
	policy := &models.Policy{
		ID:          "test-policy-empty-grants",
		Name:        "Test Policy",
		Description: "Test policy with empty directGrants",
		Rules: []*models.Rule{
			{
				Namespace:    "iot_schema",
				SchemaName:   "public",
				EntityType:   "device",
				Actions:      []string{"write", "list"},
				DirectGrants: []string{}, // Empty directGrants
			},
		},
	}
	if err := policies.AddPolicy(policy); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	// Global actions should still be allowed even with empty directGrants
	// because the rule defines the action for the entity type
	allowed, err := engine.Authorize(policies, "iot_schema", "public", "write", "device", nil)
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}
	if !allowed {
		t.Error("Expected global action 'write' to be allowed even with empty directGrants")
	}

	allowed, err = engine.Authorize(policies, "iot_schema", "public", "list", "device", nil)
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}
	if !allowed {
		t.Error("Expected global action 'list' to be allowed even with empty directGrants")
	}
}

func TestEngine_GlobalAction_WithDirectGrants(t *testing.T) {
	db := setupTestDB(t)
	dbs := map[string]*gorm.DB{
		"iot_schema": db,
	}
	schemaPaths := map[string]string{
		"iot_schema": "../../examples/iot/schemas.test.json",
	}
	engine, err := NewEngine(dbs, schemaPaths)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Create a policy with a global action and directGrants
	policies := NewPolicyRegistry()
	policy := &models.Policy{
		ID:          "test-policy-with-grants",
		Name:        "Test Policy",
		Description: "Test policy with directGrants",
		Rules: []*models.Rule{
			{
				Namespace:    "iot_schema",
				SchemaName:   "public",
				EntityType:   "device",
				Actions:      []string{"write", "list"},
				DirectGrants: []string{"device-1"},
			},
		},
	}
	if err := policies.AddPolicy(policy); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	// Global actions should be allowed when directGrants exist
	allowed, err := engine.Authorize(policies, "iot_schema", "public", "write", "device", nil)
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}
	if !allowed {
		t.Error("Expected global action 'write' to be allowed with directGrants")
	}

	allowed, err = engine.Authorize(policies, "iot_schema", "public", "list", "device", nil)
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}
	if !allowed {
		t.Error("Expected global action 'list' to be allowed with directGrants")
	}
}

func TestEngine_Authorize_GlobalAction_DeniesWhenRuleNamespaceDoesNotMatchRequest(t *testing.T) {
	db := setupTestDB(t)
	dbs := map[string]*gorm.DB{
		"iot_schema": db,
	}
	schemaPaths := map[string]string{
		"iot_schema": "../../examples/iot/schemas.test.json",
	}
	engine, err := NewEngine(dbs, schemaPaths)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	policies := NewPolicyRegistry()
	policy := &models.Policy{
		ID:          "test-policy-wrong-namespace",
		Name:        "Wrong Namespace Policy",
		Description: "Rule namespace does not match request namespace",
		Rules: []*models.Rule{
			{
				Namespace:    "other_namespace",
				SchemaName:   "public",
				EntityType:   "device",
				Actions:      []string{"list"},
				DirectGrants: []string{"*"},
			},
		},
	}
	if err := policies.AddPolicy(policy); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	allowed, err := engine.Authorize(policies, "iot_schema", "public", "list", "device", nil)
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}
	if allowed {
		t.Error("Expected deny when rule namespace does not match request namespace")
	}
}

func TestEngine_Authorize_GlobalAction_AllowsWildcardRuleSchemaAndEntity(t *testing.T) {
	db := setupTestDB(t)
	dbs := map[string]*gorm.DB{
		"iot_schema": db,
	}
	schemaPaths := map[string]string{
		"iot_schema": "../../examples/iot/schemas.test.json",
	}
	engine, err := NewEngine(dbs, schemaPaths)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	policies := NewPolicyRegistry()
	policy := &models.Policy{
		ID:          "test-policy-wildcard-entity",
		Name:        "Wildcard Entity Policy",
		Description: "Global action granted by wildcard schema/entity rule",
		Rules: []*models.Rule{
			{
				Namespace:    "iot_schema",
				SchemaName:   "*",
				EntityType:   "*",
				Actions:      []string{"list"},
				DirectGrants: []string{"*"},
			},
		},
	}
	if err := policies.AddPolicy(policy); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	allowed, err := engine.Authorize(policies, "iot_schema", "public", "list", "device", nil)
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}
	if !allowed {
		t.Error("Expected wildcard rule schemaName/entityType to allow global action")
	}
}

func TestEngine_Authorize_GlobalAction_AllowsWildcardAction(t *testing.T) {
	db := setupTestDB(t)
	dbs := map[string]*gorm.DB{
		"iot_schema": db,
	}
	schemaPaths := map[string]string{
		"iot_schema": "../../examples/iot/schemas.test.json",
	}
	engine, err := NewEngine(dbs, schemaPaths)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	policies := NewPolicyRegistry()
	policy := &models.Policy{
		ID:          "test-policy-wildcard-action",
		Name:        "Wildcard Action Policy",
		Description: "Global action granted by wildcard action rule",
		Rules: []*models.Rule{
			{
				Namespace:    "iot_schema",
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

	allowed, err := engine.Authorize(policies, "iot_schema", "public", "list", "device", nil)
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}
	if !allowed {
		t.Error("Expected wildcard action to allow global action")
	}
}

func TestEngine_GetListFilter_DoesNotUseRulesFromOtherNamespaces(t *testing.T) {
	db := setupTestDB(t)
	dbs := map[string]*gorm.DB{
		"iot_schema": db,
	}
	schemaPaths := map[string]string{
		"iot_schema": "../../examples/iot/schemas.test.json",
	}
	engine, err := NewEngine(dbs, schemaPaths)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	policies := NewPolicyRegistry()
	policy := &models.Policy{
		ID:          "test-policy-wrong-namespace-filter",
		Name:        "Wrong Namespace Filter Policy",
		Description: "Filter should ignore mismatched namespace rules",
		Rules: []*models.Rule{
			{
				Namespace:    "other_namespace",
				SchemaName:   "public",
				EntityType:   "device",
				Actions:      []string{"read"},
				DirectGrants: []string{"device-1"},
			},
		},
	}
	if err := policies.AddPolicy(policy); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	filterSQL, err := engine.GetListFilter(policies, "iot_schema", "public", "device")
	if err != nil {
		t.Fatalf("GetListFilter failed: %v", err)
	}

	if !strings.Contains(filterSQL, "1 = 0") {
		t.Errorf("Expected impossible filter when only mismatched namespace rules exist, got: %s", filterSQL)
	}
}
