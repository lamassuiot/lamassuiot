package authz

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// FilterableField declares a column that can be used as a condition in policy rules
type FilterableField struct {
	Column string `json:"column"`
	Type   string `json:"type"` // "string", "int", "float", "bool", "timestamp", "jsonb"
}

// SchemaDefinition defines the structure of an entity type
type SchemaDefinition struct {
	PrimaryKeys []string // all PK columns; always len >= 1 after loading

	EntityType    string            `json:"entityType"`
	TableName     string            `json:"tableName"`
	SchemaName    string            `json:"schemaName,omitempty"` // PostgreSQL schema name (defaults to "public" if not specified)
	Relations     []RelationConfig  `json:"relations"`
	AtomicActions []string          `json:"atomicActions"`          // Actions that require an entity key (read, write, delete, etc.)
	GlobalActions []string          `json:"globalActions"`          // Actions that don't require entity key (create, list, etc.)
	Filterable    []FilterableField `json:"filterable,omitempty"`   // Columns available for column-filter conditions in policies
	ConfigSchema  string            `json:"configSchema,omitempty"` // Config schema name (e.g., "pki", "iot") - set during loading
}

// schemaJSON is the intermediate JSON representation used when parsing schema files.
// It captures the primaryKey field as a raw JSON value so that both the string form
// ("device_id") and the array form (["tenant_id", "device_id"]) are accepted.
type schemaJSON struct {
	EntityType    string            `json:"entityType"`
	TableName     string            `json:"tableName"`
	SchemaName    string            `json:"schemaName,omitempty"`
	PrimaryKey    json.RawMessage   `json:"primaryKey"`
	Relations     []RelationConfig  `json:"relations"`
	AtomicActions []string          `json:"atomicActions"`
	GlobalActions []string          `json:"globalActions"`
	Filterable    []FilterableField `json:"filterable,omitempty"`
	ConfigSchema  string            `json:"configSchema,omitempty"`
}

// parsePrimaryKey normalises the raw JSON value for the primaryKey field into a []string.
// Accepts either a JSON string ("id") or a JSON array of strings (["tenant_id", "device_id"]).
func parsePrimaryKey(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("primaryKey is required")
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s == "" {
			return nil, fmt.Errorf("primaryKey must not be empty")
		}
		return []string{s}, nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("primaryKey must be a string or an array of strings")
	}
	return arr, nil
}

// EntityKeyCondition builds a SQL AND-condition that identifies a specific entity row using
// the provided entityKey map (column → value). The tableAlias is prepended to each column
// reference (pass QualifiedTableName() or a JOIN alias).
// Returns an error if any PrimaryKeys column is missing from entityKey, or if entityKey
// contains columns not declared in PrimaryKeys.
func (s *SchemaDefinition) EntityKeyCondition(entityKey map[string]string, tableAlias string) (string, error) {
	if err := s.ValidateEntityKey(entityKey); err != nil {
		return "", err
	}
	// Produce a deterministic order (sorted by column name) for testability.
	sortedCols := make([]string, len(s.PrimaryKeys))
	copy(sortedCols, s.PrimaryKeys)
	sort.Strings(sortedCols)

	parts := make([]string, 0, len(sortedCols))
	for _, col := range sortedCols {
		parts = append(parts, fmt.Sprintf("%s.%s = %s", tableAlias, col, sqlStringLiteral(entityKey[col])))
	}
	return strings.Join(parts, " AND "), nil
}

// ValidateEntityKey checks that entityKey contains exactly the columns declared in PrimaryKeys
// (no more, no less) and that none of the values are empty.
func (s *SchemaDefinition) ValidateEntityKey(entityKey map[string]string) error {
	for _, col := range s.PrimaryKeys {
		v, ok := entityKey[col]
		if !ok {
			return fmt.Errorf("entityKey missing required primary key column %q", col)
		}
		if v == "" {
			return fmt.Errorf("entityKey column %q must not be empty", col)
		}
	}
	for col := range entityKey {
		found := false
		for _, pk := range s.PrimaryKeys {
			if pk == col {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("entityKey contains unknown primary key column %q", col)
		}
	}
	return nil
}

// RelationConfig defines a foreign key relationship to another entity
type RelationConfig struct {
	Name         string `json:"name"`
	TargetEntity string `json:"targetEntity"`
	ForeignKey   string `json:"foreignKey"`
}

// SchemaRegistry manages all entity schemas
type SchemaRegistry struct {
	schemas      map[string]*SchemaDefinition   // Key is qualified entity type (schema.entity)
	entityLookup map[string][]*SchemaDefinition // Key is simple entity type (for fallback)
}

// NewSchemaRegistry creates a new schema registry
func NewSchemaRegistry() *SchemaRegistry {
	return &SchemaRegistry{
		schemas:      make(map[string]*SchemaDefinition),
		entityLookup: make(map[string][]*SchemaDefinition),
	}
}

// Load reads and parses schemas from a JSON file
// configSchemaName: the config schema name (e.g., "pki", "iot") that entries belong to
func (r *SchemaRegistry) Load(path string, configSchemaName string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read schema file %s: %w", path, err)
	}

	// Parse via intermediate type to handle primaryKey as string or []string
	var raws []schemaJSON
	if err := json.Unmarshal(data, &raws); err != nil {
		return fmt.Errorf("failed to parse schema JSON: %w", err)
	}

	// Convert intermediate representations to SchemaDefinition
	schemas := make([]SchemaDefinition, len(raws))
	for i, raw := range raws {
		pks, err := parsePrimaryKey(raw.PrimaryKey)
		if err != nil {
			return fmt.Errorf("invalid primaryKey for entity %s: %w", raw.EntityType, err)
		}
		schemas[i] = SchemaDefinition{
			EntityType:    raw.EntityType,
			TableName:     raw.TableName,
			SchemaName:    raw.SchemaName,
			Relations:     raw.Relations,
			AtomicActions: raw.AtomicActions,
			GlobalActions: raw.GlobalActions,
			Filterable:    raw.Filterable,
			ConfigSchema:  raw.ConfigSchema,
			PrimaryKeys:   pks,
		}
	}

	// Track schema names to detect duplicates
	schemaNames := make(map[string]bool)

	// Validate and register schemas
	for i := range schemas {
		schema := &schemas[i]
		// Set default schema name if not specified
		if schema.SchemaName == "" {
			schema.SchemaName = "public"
		}
		// Set the config schema name
		schema.ConfigSchema = configSchemaName

		if err := r.validateSchema(schema); err != nil {
			return fmt.Errorf("invalid schema for entity %s: %w", schema.EntityType, err)
		}

		// Track schema names for duplicate detection
		schemaNames[schema.SchemaName] = true

		// Check for duplicate qualified entity types
		qualifiedType := schema.QualifiedEntityType()
		if _, exists := r.schemas[qualifiedType]; exists {
			return fmt.Errorf("duplicate qualified entity type: %s (schema: %s, entity: %s)",
				qualifiedType, schema.SchemaName, schema.EntityType)
		}

		// Register with qualified entity type as key
		r.schemas[qualifiedType] = schema

		// Also maintain entity lookup for backward compatibility
		r.entityLookup[schema.EntityType] = append(r.entityLookup[schema.EntityType], schema)
	}

	return nil
}

// Get retrieves a schema by entity type (supports both qualified and unqualified)
// Qualified format: "schema_name.entity_type" (e.g., "iot_schema.device")
// Unqualified format: "entity_type" (e.g., "device") - returns first match or error if ambiguous
func (r *SchemaRegistry) Get(entityType string) (*SchemaDefinition, error) {
	// Try qualified lookup first
	if schema, exists := r.schemas[entityType]; exists {
		return schema, nil
	}

	// Fallback: try unqualified lookup for backward compatibility
	matches := r.entityLookup[entityType]
	if len(matches) == 0 {
		return nil, fmt.Errorf("schema not found for entity type: %s", entityType)
	}

	// If multiple schemas define this entity, require qualified name
	if len(matches) > 1 {
		schemaNames := make([]string, len(matches))
		for i, m := range matches {
			schemaNames[i] = m.SchemaName
		}
		return nil, fmt.Errorf("ambiguous entity type '%s' found in multiple schemas: %v. Use qualified name (schema.entity)",
			entityType, schemaNames)
	}

	return matches[0], nil
}

// GetAll returns all registered schemas
func (r *SchemaRegistry) GetAll() map[string]*SchemaDefinition {
	return r.schemas
}

// GetBySchemaEntity retrieves a schema by separated schema name and unqualified entity type.
func (r *SchemaRegistry) GetBySchemaEntity(schemaName, entityType string) (*SchemaDefinition, error) {
	matches, err := r.GetByEntity(entityType)
	if err != nil {
		return nil, err
	}

	for _, schema := range matches {
		if schema.SchemaName == schemaName {
			return schema, nil
		}
	}

	return nil, fmt.Errorf("schema not found for schemaName '%s' and entityType '%s'", schemaName, entityType)
}

// validateSchema checks if a schema definition is valid
func (r *SchemaRegistry) validateSchema(schema *SchemaDefinition) error {
	if schema.EntityType == "" {
		return fmt.Errorf("entityType is required")
	}
	if schema.TableName == "" {
		return fmt.Errorf("tableName is required")
	}
	if len(schema.PrimaryKeys) == 0 {
		return fmt.Errorf("primaryKey is required")
	}
	// Validate composite PK: no empty or duplicate column names
	seen := make(map[string]bool, len(schema.PrimaryKeys))
	for _, col := range schema.PrimaryKeys {
		if col == "" {
			return fmt.Errorf("primaryKey must not contain empty column names")
		}
		if seen[col] {
			return fmt.Errorf("primaryKey contains duplicate column %q", col)
		}
		seen[col] = true
	}

	// Validate relations
	for i, rel := range schema.Relations {
		if rel.Name == "" {
			return fmt.Errorf("relation name is required for relation at index %d", i)
		}
		if rel.TargetEntity == "" {
			return fmt.Errorf("targetEntity is required for relation %s", rel.Name)
		}
		if rel.ForeignKey == "" {
			return fmt.Errorf("foreignKey is required for relation %s", rel.Name)
		}
	}

	// Validate actions - at least one type of action must be defined
	if len(schema.AtomicActions) == 0 && len(schema.GlobalActions) == 0 {
		return fmt.Errorf("at least one action (atomic or global) must be defined")
	}

	// Validate filterable fields
	validTypes := map[string]bool{"string": true, "int": true, "float": true, "bool": true, "timestamp": true, "jsonb": true}
	for i, f := range schema.Filterable {
		if f.Column == "" {
			return fmt.Errorf("filterable field at index %d: column is required", i)
		}
		if !validTypes[f.Type] {
			return fmt.Errorf("filterable field %q: unsupported type %q (must be string, int, float, bool, timestamp, or jsonb)", f.Column, f.Type)
		}
	}

	return nil
}

// HasAction checks if a schema supports a specific action (atomic or global)
func (s *SchemaDefinition) HasAction(action string) bool {
	for _, a := range s.AtomicActions {
		if a == action {
			return true
		}
	}
	for _, a := range s.GlobalActions {
		if a == action {
			return true
		}
	}
	return false
}

// IsAtomicAction checks if an action is atomic (requires entity ID)
func (s *SchemaDefinition) IsAtomicAction(action string) bool {
	for _, a := range s.AtomicActions {
		if a == action {
			return true
		}
	}
	return false
}

// IsGlobalAction checks if an action is global (doesn't require entity ID)
func (s *SchemaDefinition) IsGlobalAction(action string) bool {
	for _, a := range s.GlobalActions {
		if a == action {
			return true
		}
	}
	return false
}

// GetRelation retrieves a relation by name
func (s *SchemaDefinition) GetRelation(name string) (*RelationConfig, error) {
	for i := range s.Relations {
		if s.Relations[i].Name == name {
			return &s.Relations[i], nil
		}
	}
	return nil, fmt.Errorf("relation %s not found in schema %s", name, s.EntityType)
}

// QualifiedEntityType returns the schema-qualified entity type
// e.g., "iot_schema.gateway" or "public.organization"
func (s *SchemaDefinition) QualifiedEntityType() string {
	return fmt.Sprintf("%s.%s", s.SchemaName, s.EntityType)
}

// NamespacedType returns the fully-qualified key used in API responses, combining the
// config namespace, the DB schema name, and the entity type.
// Format: "<namespace>.<schema_name>.<entity_type>", e.g. "iot.public.organization".
func (s *SchemaDefinition) NamespacedType() string {
	return fmt.Sprintf("%s.%s.%s", s.ConfigSchema, s.SchemaName, s.EntityType)
}

// QualifiedTableName returns the fully qualified table name (schema.table)
func (s *SchemaDefinition) QualifiedTableName() string {
	if s.SchemaName == "" || s.SchemaName == "public" {
		// For public schema or empty, just return table name (PostgreSQL default)
		return s.TableName
	}
	return fmt.Sprintf("%s.%s", s.SchemaName, s.TableName)
}

// GetFilterableField returns the FilterableField declaration for a column name, or nil if not declared.
func (s *SchemaDefinition) GetFilterableField(column string) *FilterableField {
	for i := range s.Filterable {
		if s.Filterable[i].Column == column {
			return &s.Filterable[i]
		}
	}
	return nil
}

// GetByEntity returns all schemas for a given simple entity type
func (r *SchemaRegistry) GetByEntity(entityType string) ([]*SchemaDefinition, error) {
	matches := r.entityLookup[entityType]
	if len(matches) == 0 {
		return nil, fmt.Errorf("no schemas found for entity type: %s", entityType)
	}
	return matches, nil
}
