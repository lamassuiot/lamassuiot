package authz

import (
	"fmt"
	"log"
	"strings"

	"gorm.io/gorm"
)

// Engine is the core authorization engine
type Engine struct {
	dbs     map[string]*gorm.DB // Map of config schema name -> database connection
	schemas *SchemaRegistry
}

// NewEngine creates a new authorization engine
// dbs: map of config schema name (e.g., "pki", "iot") -> database connection
// schemaPaths: map of config schema name -> schema file path
func NewEngine(dbs map[string]*gorm.DB, schemaPaths map[string]string) (*Engine, error) {
	// Load schemas
	schemas := NewSchemaRegistry()
	for configSchemaName, schemaPath := range schemaPaths {
		if err := schemas.Load(schemaPath, configSchemaName); err != nil {
			return nil, fmt.Errorf("failed to load schema %s from %s: %w", configSchemaName, schemaPath, err)
		}
		log.Printf("Loaded config schema %s from %s", configSchemaName, schemaPath)
	}
	log.Printf("Loaded %d total entity schemas", len(schemas.GetAll()))

	return &Engine{
		dbs:     dbs,
		schemas: schemas,
	}, nil
}

// Authorize checks if an action is allowed
// For atomic actions (read, write, delete, etc.): checks against a specific entity key in the database
// For global actions (create, list, etc.): checks policy grants without database queries (entityKey is ignored)
func (e *Engine) Authorize(policies *PolicyRegistry, namespace, schemaName, action, entityType string, entityKey map[string]string) (bool, error) {
	// Get schema to know table name and primary key
	schema, err := e.schemas.GetBySchemaEntity(schemaName, entityType)
	if err != nil {
		return false, fmt.Errorf("schema not found: %w", err)
	}

	if schema.ConfigSchema != namespace {
		return false, fmt.Errorf("entity type '%s' does not belong to namespace '%s'", entityType, namespace)
	}

	// Validate that the action is defined
	if !schema.HasAction(action) {
		return false, fmt.Errorf("action '%s' is not defined for entity type '%s'", action, entityType)
	}

	// Handle global actions - no database query needed, just check policy grants
	if schema.IsGlobalAction(action) {
		log.Printf("[AUTHZ] Checking global action: action=%s, entityType=%s", action, entityType)
		matchedRules := 0
		for _, rule := range policies.GetRules() {
			if ruleMatchesSchema(rule, schema) {
				matchedRules++
				if rule.HasAction(action) {
					// Check if there are any direct grants (including wildcards)
					log.Printf("[AUTHZ] ✓ GRANTED: Global action '%s' on '%s' - matched policy rule", action, entityType)
					log.Printf("[AUTHZ]   Reason: Policy rule grants action '%s' on entity type '%s'", action, entityType)
					return true, nil
				} else {
					log.Printf("[AUTHZ]   Rule for '%s' found, but action '%s' not granted", entityType, action)
				}
			}
		}
		log.Printf("[AUTHZ] ✗ DENIED: Global action '%s' on '%s'", action, entityType)
		log.Printf("[AUTHZ]   Reason: No policy rules grant this action in namespace '%s' (checked %d total rules, %d matched entity+namespace)", namespace, len(policies.GetRules()), matchedRules)
		return false, nil
	}

	// Handle atomic actions - requires database query with specific entity key
	log.Printf("[AUTHZ] Checking atomic action: action=%s, entityType=%s, entityKey=%v", action, entityType, entityKey)

	// Create filter generator with provided policies
	filterGenerator := NewFilterGenerator(e.schemas, policies)

	// Generate filter for this specific check
	log.Printf("[AUTHZ]   Generating authorization filter...")
	result, err := filterGenerator.GenerateCheckFilter(action, schemaName, entityType, entityKey)
	if err != nil {
		return false, fmt.Errorf("failed to generate filter: %w", err)
	}

	log.Printf("[AUTHZ]   Filter generated: %d condition(s), %d join(s)", len(result.Conditions), len(result.Joins))
	for i, cond := range result.Conditions {
		log.Printf("[AUTHZ]     Condition %d: %s", i+1, cond)
	}

	// If filter is impossible (1 = 0), no access
	if len(result.Conditions) == 1 && result.Conditions[0] == "1 = 0" {
		log.Printf("[AUTHZ] ✗ DENIED: action=%s, entityType=%s, entityKey=%v", action, entityType, entityKey)
		log.Printf("[AUTHZ]   Reason: No access paths found - no policy grants provide access to this entity")
		return false, nil
	}

	// Get the database connection for this schema
	db, err := e.getDBForSchema(schema)
	if err != nil {
		return false, fmt.Errorf("failed to get database connection: %w", err)
	}

	// Build query with JOINs and WHERE conditions
	var exists int
	query := db.Table(schema.QualifiedTableName())

	// Add JOINs
	for i, join := range result.Joins {
		log.Printf("[AUTHZ]     Join %d: %s", i+1, join)
		query = query.Joins(join)
	}

	// Add WHERE conditions
	// For check filters, conditions are already properly combined (access conditions AND entity key)
	whereClause := strings.Join(result.Conditions, " AND ")
	log.Printf("[AUTHZ]   Executing database query on table '%s'", schema.QualifiedTableName())
	log.Printf("[AUTHZ]   WHERE: %s", whereClause)

	query = query.Where(whereClause).Select("1").Limit(1).Find(&exists)

	if query.Error != nil {
		return false, fmt.Errorf("database query failed: %w", query.Error)
	}

	authorized := query.RowsAffected > 0
	log.Printf("[AUTHZ]   Query result: found %d matching record(s)", query.RowsAffected)

	if authorized {
		log.Printf("[AUTHZ] ✓ GRANTED: action=%s, entityType=%s, entityKey=%v", action, entityType, entityKey)
		log.Printf("[AUTHZ]   Reason: Entity exists in database and matches at least one policy rule condition")
	} else {
		log.Printf("[AUTHZ] ✗ DENIED: action=%s, entityType=%s, entityKey=%v", action, entityType, entityKey)
		log.Printf("[AUTHZ]   Reason: Entity either doesn't exist or doesn't match any policy rule conditions")
	}

	return authorized, nil
}

// GetListFilter returns a SQL filter for listing entities based on policy directGrants
// Uses the implicit "read" action to determine which entities can be listed
func (e *Engine) GetListFilter(policies *PolicyRegistry, namespace, schemaName, entityType string) (string, error) {
	schema, err := e.schemas.GetBySchemaEntity(schemaName, entityType)
	if err != nil {
		return "", fmt.Errorf("schema not found: %w", err)
	}

	if schema.ConfigSchema != namespace {
		return "", fmt.Errorf("entity type '%s' does not belong to namespace '%s'", entityType, namespace)
	}

	// Create filter generator with provided policies
	filterGenerator := NewFilterGenerator(e.schemas, policies)

	result, err := filterGenerator.GenerateListFilter("read", schemaName, entityType)
	if err != nil {
		return "", fmt.Errorf("failed to generate filter: %w", err)
	}

	return result.FullSQL, nil
}

// GetSchemas returns the schema registry (useful for introspection)
func (e *Engine) GetSchemas() *SchemaRegistry {
	return e.schemas
}

// getDBForSchema returns the database connection for a given schema definition
func (e *Engine) getDBForSchema(schema *SchemaDefinition) (*gorm.DB, error) {
	db, exists := e.dbs[schema.ConfigSchema]
	if !exists {
		return nil, fmt.Errorf("no database connection configured for config schema '%s' (entity: %s)", schema.ConfigSchema, schema.EntityType)
	}
	return db, nil
}
