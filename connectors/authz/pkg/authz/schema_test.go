package authz

import (
	"os"
	"testing"
)

func TestLoadIoTSchemas(t *testing.T) {
	registry := NewSchemaRegistry()

	err := registry.Load("../../examples/iot/schemas.json", "iot")
	if err != nil {
		t.Fatalf("Failed to load IoT schemas: %v", err)
	}

	// Verify all entity types loaded
	entityTypes := []string{"organization", "building", "gateway", "device"}
	for _, entityType := range entityTypes {
		schema, err := registry.Get(entityType)
		if err != nil {
			t.Errorf("Failed to get schema for %s: %v", entityType, err)
		}
		if schema.EntityType != entityType {
			t.Errorf("Expected entityType %s, got %s", entityType, schema.EntityType)
		}
	}

	// Verify device schema details
	deviceSchema, _ := registry.Get("device")
	if deviceSchema.TableName != "iot_devices" {
		t.Errorf("Expected tableName 'iot_devices', got '%s'", deviceSchema.TableName)
	}
	if len(deviceSchema.PrimaryKeys) != 1 || deviceSchema.PrimaryKeys[0] != "device_id" {
		t.Errorf("Expected primaryKey 'device_id', got %v", deviceSchema.PrimaryKeys)
	}
	// Note: 'read' and 'list' are implicit actions, not defined in schema
	if !deviceSchema.HasAction("control") {
		t.Error("Expected device schema to have 'control' action")
	}
}

func TestSchemaRegistry_Load(t *testing.T) {
	testSchema := `[
  {
    "entityType": "device",
    "tableName": "devices",
    "primaryKey": "id",
    "relations": [
      {
        "name": "owner",
        "targetEntity": "user",
        "foreignKey": "owner_id"
      }
    ],
    "atomicActions": ["read", "write"],
    "globalActions": ["create", "list"]
  }
]`

	tmpFile, err := os.CreateTemp("", "test_schema_*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(testSchema)); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	registry := NewSchemaRegistry()
	if err := registry.Load(tmpFile.Name(), "test"); err != nil {
		t.Fatalf("failed to load schema: %v", err)
	}

	schema, err := registry.Get("device")
	if err != nil {
		t.Fatalf("failed to get schema: %v", err)
	}

	if schema.EntityType != "device" {
		t.Errorf("expected entityType 'device', got '%s'", schema.EntityType)
	}
	if schema.TableName != "devices" {
		t.Errorf("expected tableName 'devices', got '%s'", schema.TableName)
	}
	if len(schema.PrimaryKeys) != 1 || schema.PrimaryKeys[0] != "id" {
		t.Errorf("expected primaryKey 'id', got %v", schema.PrimaryKeys)
	}
	if len(schema.AtomicActions) != 2 {
		t.Errorf("expected 2 atomic actions, got %d", len(schema.AtomicActions))
	}
	if len(schema.GlobalActions) != 2 {
		t.Errorf("expected 2 global actions, got %d", len(schema.GlobalActions))
	}
}

func TestSchemaRegistry_Get_NotFound(t *testing.T) {
	registry := NewSchemaRegistry()
	_, err := registry.Get("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent schema")
	}
}

func TestSchemaDefinition_HasAction(t *testing.T) {
	schema := &SchemaDefinition{
		EntityType:    "device",
		TableName:     "devices",
		PrimaryKeys:   []string{"id"},
		AtomicActions: []string{"read", "write"},
		GlobalActions: []string{"create", "list"},
		Relations:     []RelationConfig{},
	}

	if !schema.HasAction("read") {
		t.Error("expected schema to have 'read' action")
	}
	if !schema.HasAction("write") {
		t.Error("expected schema to have 'write' action")
	}
	if !schema.HasAction("create") {
		t.Error("expected schema to have 'create' action")
	}
	if schema.HasAction("delete") {
		t.Error("expected schema not to have 'delete' action")
	}

	// Test IsAtomicAction
	if !schema.IsAtomicAction("read") {
		t.Error("expected 'read' to be an atomic action")
	}
	if schema.IsAtomicAction("create") {
		t.Error("expected 'create' not to be an atomic action")
	}

	// Test IsGlobalAction
	if !schema.IsGlobalAction("create") {
		t.Error("expected 'create' to be a global action")
	}
	if schema.IsGlobalAction("read") {
		t.Error("expected 'read' not to be a global action")
	}
}

func TestSchemaDefinition_GetRelation(t *testing.T) {
	schema := &SchemaDefinition{
		EntityType:    "device",
		TableName:     "devices",
		PrimaryKeys:   []string{"id"},
		AtomicActions: []string{"read"},
		Relations: []RelationConfig{
			{
				Name:         "owner",
				TargetEntity: "user",
				ForeignKey:   "owner_id",
			},
		},
	}

	rel, err := schema.GetRelation("owner")
	if err != nil {
		t.Fatalf("failed to get relation: %v", err)
	}
	if rel.TargetEntity != "user" {
		t.Errorf("expected targetEntity 'user', got '%s'", rel.TargetEntity)
	}

	_, err = schema.GetRelation("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent relation")
	}
}

func TestSchemaValidation(t *testing.T) {
	tests := []struct {
		name        string
		schema      SchemaDefinition
		shouldError bool
	}{
		{
			name: "valid schema",
			schema: SchemaDefinition{
				EntityType:    "device",
				TableName:     "devices",
				PrimaryKeys:   []string{"id"},
				AtomicActions: []string{"read"},
				Relations:     []RelationConfig{},
			},
			shouldError: false,
		},
		{
			name: "valid schema with global actions",
			schema: SchemaDefinition{
				EntityType:    "device",
				TableName:     "devices",
				PrimaryKeys:   []string{"id"},
				GlobalActions: []string{"create"},
				Relations:     []RelationConfig{},
			},
			shouldError: false,
		},
		{
			name: "missing entityType",
			schema: SchemaDefinition{
				TableName:     "devices",
				PrimaryKeys:   []string{"id"},
				AtomicActions: []string{"read"},
				Relations:     []RelationConfig{},
			},
			shouldError: true,
		},
		{
			name: "missing tableName",
			schema: SchemaDefinition{
				EntityType:    "device",
				PrimaryKeys:   []string{"id"},
				AtomicActions: []string{"read"},
				Relations:     []RelationConfig{},
			},
			shouldError: true,
		},
		{
			name: "missing primaryKey",
			schema: SchemaDefinition{
				EntityType:    "device",
				TableName:     "devices",
				AtomicActions: []string{"read"},
				Relations:     []RelationConfig{},
			},
			shouldError: true,
		},
		{
			name: "missing all actions",
			schema: SchemaDefinition{
				EntityType:  "device",
				TableName:   "devices",
				PrimaryKeys: []string{"id"},
				Relations:   []RelationConfig{},
			},
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := NewSchemaRegistry()
			err := registry.validateSchema(&tt.schema)
			if tt.shouldError && err == nil {
				t.Error("expected validation error")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}
