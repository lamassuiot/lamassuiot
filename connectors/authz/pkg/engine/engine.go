package engine

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
	dbs         map[string]*gorm.DB // Map of config schema name -> database connection
	schemas     *SchemaRegistry
	httpSchemas *HTTPSchemaRegistry
	logger      *logrus.Entry
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

// Logger returns the engine's logrus.Entry (used by the service layer for capability logging).
func (e *Engine) Logger() *logrus.Entry {
	return e.logger
}

// NewEngine creates a new authorization engine
// dbs: map of config schema name (e.g., "pki", "iot") -> database connection
// schemaPaths: map of config schema name -> schema file path
func NewEngine(dbs map[string]*gorm.DB, schemaPaths map[string]string, opts ...EngineOption) (*Engine, error) {
	schemas := NewSchemaRegistry()
	for configSchemaName, schemaPath := range schemaPaths {
		if err := schemas.Load(schemaPath, configSchemaName); err != nil {
			return nil, fmt.Errorf("failed to load schema %s from %s: %w", configSchemaName, schemaPath, err)
		}
	}

	e := &Engine{
		dbs:         dbs,
		schemas:     schemas,
		httpSchemas: NewHTTPSchemaRegistry(),
		logger:      engineNopLogger(),
	}

	for _, opt := range opts {
		opt(e)
	}

	e.logger.WithFields(logrus.Fields{"schema_count": len(schemas.GetAll())}).Debug("engine schemas loaded")

	return e, nil
}

// Authorize checks if an action is allowed.
// For atomic actions: checks against a specific entity key in the database.
// For global actions: checks policy grants without database queries (entityKey is ignored).
func (e *Engine) Authorize(ctx context.Context, policies *PolicyRegistry, namespace, schemaName, action, entityType string, entityKey map[string]string) (bool, error) {
	log := helpers.ConfigureLogger(ctx, e.logger)
	schema, err := e.schemas.GetBySchemaEntity(schemaName, entityType)
	if err != nil {
		return false, fmt.Errorf("schema not found: %w", err)
	}
	if schema.ConfigSchema != namespace {
		return false, fmt.Errorf("entity type '%s' does not belong to namespace '%s'", entityType, namespace)
	}
	if !schema.HasAction(action) {
		return false, fmt.Errorf("action '%s' is not defined for entity type '%s'", action, entityType)
	}
	if schema.IsGlobalAction(action) {
		return e.authorizeGlobal(log, policies, schema, action, entityType, namespace)
	}
	return e.authorizeAtomic(ctx, policies, schema, schemaName, action, entityType, namespace, entityKey)
}

func (e *Engine) authorizeGlobal(log *logrus.Entry, policies *PolicyRegistry, schema *SchemaDefinition, action, entityType, namespace string) (bool, error) {
	matchedRules := 0
	for _, rule := range policies.GetRules() {
		if ruleMatchesSchema(rule, schema) {
			matchedRules++
			if rule.HasAction(action) {
				log.WithFields(logrus.Fields{
					"action": action, "entity_type": entityType, "namespace": namespace,
					"allowed": true, "reason": "global action granted by policy rule",
				}).Info("authorization decision")
				return true, nil
			}
		}
	}
	log.WithFields(logrus.Fields{
		"action": action, "entity_type": entityType, "namespace": namespace,
		"allowed": false, "reason": "no policy rule grants this action",
		"rules_checked": len(policies.GetRules()), "rules_matched": matchedRules,
	}).Info("authorization decision")
	return false, nil
}

func (e *Engine) authorizeAtomic(ctx context.Context, policies *PolicyRegistry, schema *SchemaDefinition, schemaName, action, entityType, namespace string, entityKey map[string]string) (bool, error) {
	log := helpers.ConfigureLogger(ctx, e.logger)
	filterGenerator, err := NewFilterGenerator(e.schemas, policies)
	if err != nil {
		return false, fmt.Errorf("failed to build authorization graph: %w", err)
	}
	result, err := filterGenerator.GenerateCheckFilter(action, schemaName, entityType, entityKey)
	if err != nil {
		return false, fmt.Errorf("failed to generate filter: %w", err)
	}
	if len(result.Conditions) == 1 && result.Conditions[0] == "1 = 0" {
		log.WithFields(logrus.Fields{
			"action": action, "entity_type": entityType, "namespace": namespace,
			"allowed": false, "reason": "no policy grants access to this entity",
		}).Info("authorization decision")
		return false, nil
	}
	log.WithFields(logrus.Fields{
		"action": action, "entity_type": entityType,
		"condition_count": len(result.Conditions), "join_count": len(result.Joins),
	}).Debug("authorization filter generated")
	db, err := e.getDBForSchema(schema)
	if err != nil {
		return false, fmt.Errorf("failed to get database connection: %w", err)
	}
	var exists int
	query := db.WithContext(ctx).Table(schema.QualifiedTableName())
	for _, join := range result.Joins {
		query = query.Joins(join)
	}
	whereClause := strings.Join(result.Conditions, " AND ")
	log.WithFields(logrus.Fields{
		"action": action, "entity_type": entityType, "where_clause": whereClause,
	}).Trace("authorization filter detail")
	query = query.Where(whereClause).Select("1").Limit(1).Find(&exists)
	if query.Error != nil {
		return false, fmt.Errorf("database query failed: %w", query.Error)
	}
	authorized := query.RowsAffected > 0
	fields := logrus.Fields{
		"action": action, "entity_type": entityType, "namespace": namespace,
		"allowed": authorized, "reason": "denied: entity key did not match any policy-permitted entity",
	}
	if authorized {
		fields["reason"] = "allowed: entity key matched policy conditions"
		var matchedPolicyIDs []string
		for _, policy := range policies.GetAll() {
			for _, rule := range policy.Rules {
				if ruleMatchesSchema(rule, schema) && rule.HasAction(action) {
					matchedPolicyIDs = append(matchedPolicyIDs, policy.ID)
					break
				}
			}
		}
		if len(matchedPolicyIDs) > 0 {
			fields["policy_ids"] = matchedPolicyIDs
		}
	}
	log.WithFields(fields).Info("authorization decision")
	return authorized, nil
}

// GetListFilter returns a SQL filter for listing entities based on policy rules.
func (e *Engine) GetListFilter(ctx context.Context, policies *PolicyRegistry, namespace, schemaName, entityType string) (string, error) {
	log := helpers.ConfigureLogger(ctx, e.logger)
	schema, err := e.schemas.GetBySchemaEntity(schemaName, entityType)
	if err != nil {
		return "", fmt.Errorf("schema not found: %w", err)
	}

	if schema.ConfigSchema != namespace {
		return "", fmt.Errorf("entity type '%s' does not belong to namespace '%s'", entityType, namespace)
	}

	filterGenerator, err := NewFilterGenerator(e.schemas, policies)
	if err != nil {
		return "", fmt.Errorf("failed to build authorization graph: %w", err)
	}

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

// GetSchemas returns the entity schema registry (for introspection).
func (e *Engine) GetSchemas() *SchemaRegistry {
	return e.schemas
}

// GetHTTPSchemas returns the HTTP schema registry (for introspection).
func (e *Engine) GetHTTPSchemas() *HTTPSchemaRegistry {
	return e.httpSchemas
}

// WithHTTPSchemas returns an EngineOption that loads HTTP schema JSON files into the engine.
// Files that fail to load are logged and skipped — startup is not aborted.
func WithHTTPSchemas(paths []string) EngineOption {
	return func(e *Engine) {
		for _, p := range paths {
			if err := e.httpSchemas.Load(p); err != nil {
				e.logger.WithError(err).Errorf("http schema load failed: %s", p)
			}
		}
	}
}

// CheckHTTP reports whether the policies in the registry grant access to the given
// HTTP method+path combination. It iterates all HTTPRules across all policies and
// returns on the first positive match (allow-first semantics).
// Missing schema references are skipped without error to tolerate rolling deployments
// where a schema file may not yet be present on all instances.
func (e *Engine) CheckHTTP(ctx context.Context, policies *PolicyRegistry, method, path string) (allowed bool, matchedPolicyID string, err error) {
	result, err := e.CheckHTTPRequest(ctx, HTTPCheckRequest{
		Method: method,
		Path:   path,
		Subjects: []SubjectPolicySet{
			{
				Subject:  ResolvedSubject{Attributes: map[string]string{}},
				Policies: policies,
			},
		},
	})
	if err != nil {
		return false, "", err
	}
	return result.Allowed, result.MatchedPolicyID, nil
}

// CheckHTTPRequest evaluates HTTP route action grants plus optional route
// constraints against each subject independently.
func (e *Engine) CheckHTTPRequest(ctx context.Context, req HTTPCheckRequest) (HTTPCheckResult, error) {
	for _, subjectPolicies := range req.Subjects {
		if subjectPolicies.Policies == nil {
			continue
		}
		for _, policy := range subjectPolicies.Policies.GetAll() {
			for _, httpRule := range policy.HTTPRules {
				schema, schemaErr := e.httpSchemas.Get(httpRule.SchemaName)
				if schemaErr != nil {
					continue // schema not loaded on this instance — skip
				}
				route := schema.MatchRoute(req.Method, req.Path)
				if route == nil {
					continue
				}
				if !httpRule.HasHTTPAction(route.Action) {
					continue
				}
				if !httpRouteConstraintsMatch(route, req, subjectPolicies.Subject) {
					continue
				}
				return HTTPCheckResult{
					Allowed:            true,
					MatchedPolicyID:    policy.ID,
					MatchedPrincipalID: subjectPolicies.Subject.PrincipalID,
					MatchedAction:      route.Action,
				}, nil
			}
		}
	}
	return HTTPCheckResult{}, nil
}

func (e *Engine) getDBForSchema(schema *SchemaDefinition) (*gorm.DB, error) {
	db, exists := e.dbs[schema.ConfigSchema]
	if !exists {
		return nil, fmt.Errorf("no database connection configured for config schema '%s' (entity: %s)", schema.ConfigSchema, schema.EntityType)
	}
	return db, nil
}
