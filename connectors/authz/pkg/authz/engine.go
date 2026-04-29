package authz

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// Engine is the core authorization engine
type Engine struct {
	dbs     map[string]*gorm.DB // Map of config schema name -> database connection
	schemas *SchemaRegistry
	logger  *logrus.Entry
}

// EngineOption is a functional option for Engine.
type EngineOption func(*Engine)

// WithLogger injects a logrus.Entry into the Engine.
func WithLogger(l *logrus.Entry) EngineOption {
	return func(e *Engine) { e.logger = l }
}

func engineNopLogger() *logrus.Entry {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return logrus.NewEntry(l)
}

// NewEngine creates a new authorization engine
// dbs: map of config schema name (e.g., "pki", "iot") -> database connection
// schemaPaths: map of config schema name -> schema file path
func NewEngine(dbs map[string]*gorm.DB, schemaPaths map[string]string, opts ...EngineOption) (*Engine, error) {
	// Load schemas
	schemas := NewSchemaRegistry()
	for configSchemaName, schemaPath := range schemaPaths {
		if err := schemas.Load(schemaPath, configSchemaName); err != nil {
			return nil, fmt.Errorf("failed to load schema %s from %s: %w", configSchemaName, schemaPath, err)
		}
	}

	e := &Engine{
		dbs:     dbs,
		schemas: schemas,
		logger:  engineNopLogger(),
	}

	for _, opt := range opts {
		opt(e)
	}

	e.logger.WithFields(logrus.Fields{"schema_count": len(schemas.GetAll())}).Debug("engine schemas loaded")

	return e, nil
}

// Authorize checks if an action is allowed
// For atomic actions (read, write, delete, etc.): checks against a specific entity key in the database
// For global actions (create, list, etc.): checks policy grants without database queries (entityKey is ignored)
func (e *Engine) Authorize(ctx context.Context, policies *PolicyRegistry, namespace, schemaName, action, entityType string, entityKey map[string]string) (bool, error) {
	log := helpers.ConfigureLogger(ctx, e.logger)
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
		matchedRules := 0
		for _, rule := range policies.GetRules() {
			if ruleMatchesSchema(rule, schema) {
				matchedRules++
				if rule.HasAction(action) {
					log.WithFields(logrus.Fields{
						"action":      action,
						"entity_type": entityType,
						"namespace":   namespace,
						"allowed":     true,
						"reason":      "global action granted by policy rule",
					}).Info("authorization decision")
					return true, nil
				}
			}
		}
		log.WithFields(logrus.Fields{
			"action":        action,
			"entity_type":   entityType,
			"namespace":     namespace,
			"allowed":       false,
			"reason":        "no policy rule grants this action",
			"rules_checked": len(policies.GetRules()),
			"rules_matched": matchedRules,
		}).Info("authorization decision")
		return false, nil
	}

	// Handle atomic actions - requires database query with specific entity key

	// Create filter generator with provided policies
	filterGenerator := NewFilterGenerator(e.schemas, policies)

	// Generate filter for this specific check
	result, err := filterGenerator.GenerateCheckFilter(action, schemaName, entityType, entityKey)
	if err != nil {
		return false, fmt.Errorf("failed to generate filter: %w", err)
	}

	// If filter is impossible (1 = 0), no access
	if len(result.Conditions) == 1 && result.Conditions[0] == "1 = 0" {
		log.WithFields(logrus.Fields{
			"action":      action,
			"entity_type": entityType,
			"namespace":   namespace,
			"allowed":     false,
			"reason":      "no policy grants access to this entity",
		}).Info("authorization decision")
		return false, nil
	}

	log.WithFields(logrus.Fields{
		"action":          action,
		"entity_type":     entityType,
		"condition_count": len(result.Conditions),
		"join_count":      len(result.Joins),
	}).Debug("authorization filter generated")

	// Get the database connection for this schema
	db, err := e.getDBForSchema(schema)
	if err != nil {
		return false, fmt.Errorf("failed to get database connection: %w", err)
	}

	// Build query with JOINs and WHERE conditions
	var exists int
	query := db.Table(schema.QualifiedTableName())

	// Add JOINs
	for _, join := range result.Joins {
		query = query.Joins(join)
	}

	// Add WHERE conditions
	// For check filters, conditions are already properly combined (access conditions AND entity key)
	whereClause := strings.Join(result.Conditions, " AND ")

	log.WithFields(logrus.Fields{
		"action":       action,
		"entity_type":  entityType,
		"where_clause": whereClause,
	}).Trace("authorization filter detail")

	query = query.Where(whereClause).Select("1").Limit(1).Find(&exists)

	if query.Error != nil {
		return false, fmt.Errorf("database query failed: %w", query.Error)
	}

	authorized := query.RowsAffected > 0

	reason := "entity not found or does not match policy conditions"
	if authorized {
		reason = "entity found matching policy conditions"
	}

	log.WithFields(logrus.Fields{
		"action":      action,
		"entity_type": entityType,
		"namespace":   namespace,
		"allowed":     authorized,
		"reason":      reason,
	}).Info("authorization decision")

	return authorized, nil
}

// GetListFilter returns a SQL filter for listing entities based on policy directGrants
// Uses the implicit "read" action to determine which entities can be listed
func (e *Engine) GetListFilter(ctx context.Context, policies *PolicyRegistry, namespace, schemaName, entityType string) (string, error) {
	log := helpers.ConfigureLogger(ctx, e.logger)
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

	log.WithFields(logrus.Fields{
		"namespace":       namespace,
		"schema":          schemaName,
		"entity_type":     entityType,
		"condition_count": len(result.Conditions),
		"join_count":      len(result.Joins),
	}).Debug("list filter generated")

	log.WithFields(logrus.Fields{
		"namespace":   namespace,
		"schema":      schemaName,
		"entity_type": entityType,
		"filter_sql":  result.FullSQL,
	}).Trace("list filter SQL")

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
