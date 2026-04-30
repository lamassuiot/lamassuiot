package engine

import (
	"fmt"
	"strings"

	"github.com/lamassuiot/authz/pkg/models"
)

// FilterGenerator generates SQL WHERE clauses for authorization
type FilterGenerator struct {
	schemas  *SchemaRegistry
	policies *PolicyRegistry
	graph    *AuthorizationGraph
}

// NewFilterGenerator creates a new filter generator
func NewFilterGenerator(schemas *SchemaRegistry, policies *PolicyRegistry) *FilterGenerator {
	graph := NewAuthorizationGraph()
	if err := graph.BuildFromPoliciesAndSchemas(policies, schemas); err != nil {
		// Log error but continue - graph will be empty
		fmt.Printf("Warning: failed to build authorization graph: %v\n", err)
	}

	return &FilterGenerator{
		schemas:  schemas,
		policies: policies,
		graph:    graph,
	}
}

// FilterResult contains the generated filter components
type FilterResult struct {
	Joins      []string
	Conditions []string
	FullSQL    string // Complete SQL query with SELECT, FROM, JOINs, and WHERE
}

func sqlStringLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// formatColumnFilterValue formats a Go value (from JSON unmarshaling) into a SQL literal.
// JSON numbers unmarshal as float64; booleans as bool; strings as string; arrays as []interface{}.
func formatColumnFilterValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		return sqlStringLiteral(val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	case float64:
		formatted := fmt.Sprintf("%g", val)
		return formatted
	case []interface{}:
		parts := make([]string, len(val))
		for i, item := range val {
			parts[i] = formatColumnFilterValue(item)
		}
		return "(" + strings.Join(parts, ", ") + ")"
	default:
		return fmt.Sprintf("%v", v)
	}
}

// buildColumnFilterConditions converts a rule's ColumnFilters into a single SQL condition string.
// Multiple filters are ANDed together. Returns empty string if no filters.
// Returns an error if a column is not declared as filterable in the schema.
func buildColumnFilterConditions(schema *SchemaDefinition, cf []models.ColumnFilter) (string, error) {
	return buildColumnFilterConditionsWithPrefix(schema, cf, schema.QualifiedTableName())
}

// buildColumnFilterConditionsWithPrefix is like buildColumnFilterConditions but uses a custom
// table prefix (e.g. a JOIN alias) instead of the schema's qualified table name.
func buildColumnFilterConditionsWithPrefix(schema *SchemaDefinition, cf []models.ColumnFilter, tablePrefix string) (string, error) {
	if len(cf) == 0 {
		return "", nil
	}

	operatorSQL := map[string]string{
		"eq":   "=",
		"neq":  "!=",
		"gt":   ">",
		"gte":  ">=",
		"lt":   "<",
		"lte":  "<=",
		"in":   "IN",
		"like": "LIKE",
	}

	parts := make([]string, 0, len(cf))
	for _, filter := range cf {
		field := schema.GetFilterableField(filter.Column)
		if field == nil {
			return "", fmt.Errorf("column %q is not declared as filterable in schema %s", filter.Column, schema.EntityType)
		}

		if filter.Type != "" && filter.Type != field.Type {
			return "", fmt.Errorf("column %q: filter declares type %q but schema declares %q", filter.Column, filter.Type, field.Type)
		}

		op, ok := operatorSQL[filter.Operator]
		if !ok {
			return "", fmt.Errorf("unsupported operator %q for column %q", filter.Operator, filter.Column)
		}

		colRef := fmt.Sprintf("%s.%s", tablePrefix, filter.Column)
		parts = append(parts, fmt.Sprintf("%s %s %s", colRef, op, formatColumnFilterValue(filter.Value)))
	}

	return strings.Join(parts, " AND "), nil
}

// buildFullSQL constructs the complete SQL query from filter components
func (r *FilterResult) buildFullSQL(schema *SchemaDefinition, conditionOperator string) {
	var sqlBuilder strings.Builder
	sqlBuilder.WriteString("SELECT * FROM ")
	sqlBuilder.WriteString(schema.QualifiedTableName())

	// Add JOINs
	if len(r.Joins) > 0 {
		sqlBuilder.WriteString(" ")
		sqlBuilder.WriteString(strings.Join(r.Joins, " "))
	}

	// Add WHERE clause
	if len(r.Conditions) > 0 {
		sqlBuilder.WriteString(" WHERE ")
		sqlBuilder.WriteString(strings.Join(r.Conditions, conditionOperator))
	}

	r.FullSQL = sqlBuilder.String()
}

// GenerateListFilter generates JOIN clauses and WHERE conditions for listing entities
func (fg *FilterGenerator) GenerateListFilter(action, targetSchemaName, targetEntityType string) (*FilterResult, error) {
	schema, err := fg.schemas.GetBySchemaEntity(targetSchemaName, targetEntityType)
	if err != nil {
		return nil, fmt.Errorf("schema not found: %w", err)
	}

	targetQualifiedEntityType := schema.QualifiedEntityType()

	result := &FilterResult{
		Joins:      []string{},
		Conditions: []string{},
	}

	// Track global path index to ensure unique table aliases across all paths from different entity types
	pathCounter := 0

	// 1. Check direct grants from rules that match both entityType AND action
	for _, rule := range fg.policies.GetRules() {
		if !ruleMatchesSchema(rule, schema) {
			continue
		}
		if !rule.HasAction(action) {
			continue // This rule doesn't support the requested action
		}
		if rule.HasDirectGrants() {
			// Check for wildcard "*" grant
			for _, entityID := range rule.GetDirectGrants() {
				if entityID == "*" {
					// Wildcard grants access to ALL entities
					result.Conditions = append(result.Conditions, "1 = 1")
					return result, nil
				}
			}
			// No wildcard, collect all entity IDs for this rule
			grants := rule.GetDirectGrants()
			if len(grants) > 0 {
				// Build IN clause with escaped SQL string literals
				quotedGrants := make([]string, len(grants))
				for i, grant := range grants {
					quotedGrants[i] = sqlStringLiteral(grant)
				}
				// Qualify the column name with the table name to avoid ambiguity
				result.Conditions = append(result.Conditions, fmt.Sprintf("%s.%s IN (%s)",
					schema.QualifiedTableName(), schema.PrimaryKeys[0], strings.Join(quotedGrants, ", ")))
			}
		}

		if rule.HasColumnFilters() {
			cond, err := buildColumnFilterConditions(schema, rule.ColumnFilters)
			if err != nil {
				return nil, fmt.Errorf("column filter error in rule for %s: %w", rule.QualifiedEntityType(), err)
			}
			if cond != "" {
				result.Conditions = append(result.Conditions, cond)
			}
		}
	}

	// 2. Check cascading access from other entity types' directGrants
	for _, otherRule := range fg.policies.GetRules() {
		for _, sourceSchema := range fg.schemas.GetAll() {
			if !ruleMatchesSchema(otherRule, sourceSchema) {
				continue
			}

			if sourceSchema.QualifiedEntityType() == targetQualifiedEntityType {
				continue // Already handled above
			}

			concreteRule := concretizeRuleForSchema(otherRule, sourceSchema)

			if concreteRule.HasDirectGrants() {
				// Check for wildcard "*" grant
				hasWildcard := false
				for _, entityID := range concreteRule.GetDirectGrants() {
					if entityID == "*" {
						hasWildcard = true
						break
					}
				}

				if hasWildcard {
					// Wildcard - cascade from ALL entities of this type
					cascadeResult, newPathCounter, err := fg.buildCascadingAccessWildcard(
						concreteRule,
						action,
						targetQualifiedEntityType,
						pathCounter,
					)
					if err != nil {
						return nil, err
					}
					pathCounter = newPathCounter
					result.Joins = append(result.Joins, cascadeResult.Joins...)
					result.Conditions = append(result.Conditions, cascadeResult.Conditions...)
				} else {
					// Specific entity IDs
					for _, entityID := range concreteRule.GetDirectGrants() {
						cascadeResult, newPathCounter, err := fg.buildCascadingAccess(
							concreteRule,
							entityID,
							action,
							targetQualifiedEntityType,
							pathCounter,
						)
						if err != nil {
							return nil, err
						}
						pathCounter = newPathCounter
						result.Joins = append(result.Joins, cascadeResult.Joins...)
						result.Conditions = append(result.Conditions, cascadeResult.Conditions...)
					}
				}
			} else if concreteRule.HasColumnFilters() {
				// Attribute-based cascading
				cascadeResult, newPathCounter, err := fg.buildCascadingAccessByColumnFilter(
					concreteRule,
					action,
					targetQualifiedEntityType,
					pathCounter,
				)
				if err != nil {
					return nil, err
				}
				pathCounter = newPathCounter
				result.Joins = append(result.Joins, cascadeResult.Joins...)
				result.Conditions = append(result.Conditions, cascadeResult.Conditions...)
			}
		}
	}

	if len(result.Conditions) == 0 {
		result.Conditions = append(result.Conditions, "1 = 0")
	}

	// Build the complete SQL query
	result.buildFullSQL(schema, " OR ")

	return result, nil
}

// GenerateCheckFilter generates JOIN clauses and WHERE conditions for checking single entity access
func (fg *FilterGenerator) GenerateCheckFilter(action, schemaName, entityType string, entityKey map[string]string) (*FilterResult, error) {
	schema, err := fg.schemas.GetBySchemaEntity(schemaName, entityType)
	if err != nil {
		return nil, fmt.Errorf("schema not found: %w", err)
	}

	// Get base filter for listing
	result, err := fg.GenerateListFilter(action, schemaName, entityType)
	if err != nil {
		return nil, err
	}

	// If no access at all, return early
	if len(result.Conditions) == 1 && result.Conditions[0] == "1 = 0" {
		return result, nil
	}

	// Wrap access conditions in parentheses and AND with entity key check
	accessCondition := "(" + strings.Join(result.Conditions, " OR ") + ")"
	entityKeyCondition, err := schema.EntityKeyCondition(entityKey, schema.QualifiedTableName())
	if err != nil {
		return nil, fmt.Errorf("invalid entityKey: %w", err)
	}

	// Replace conditions with the combined condition
	result.Conditions = []string{accessCondition, entityKeyCondition}

	return result, nil
}

// buildCascadingAccess uses the graph to find paths from owned entity to target
func (fg *FilterGenerator) buildCascadingAccess(rule *models.Rule, ownedEntityID string, action string, targetEntityType string, startPathIdx int) (*FilterResult, int, error) {
	result := &FilterResult{
		Joins:      []string{},
		Conditions: []string{},
	}

	pathIdx := startPathIdx

	paths := fg.graph.FindPathsBetween(rule.QualifiedEntityType(), targetEntityType, action, 10)

	for _, path := range paths {
		if !fg.pathAllowedByRule(rule, path, action) {
			continue
		}
		pathResult, err := fg.buildPathFilter(rule.QualifiedEntityType(), ownedEntityID, path, pathIdx)
		if err != nil {
			return nil, pathIdx, err
		}
		if len(pathResult.Conditions) > 0 || len(pathResult.Joins) > 0 {
			result.Joins = append(result.Joins, pathResult.Joins...)
			result.Conditions = append(result.Conditions, pathResult.Conditions...)
			pathIdx++
		}
	}

	return result, pathIdx, nil
}

// buildCascadingAccessWildcard builds cascading access from ALL entities of a type (wildcard)
func (fg *FilterGenerator) buildCascadingAccessWildcard(rule *models.Rule, action string, targetEntityType string, startPathIdx int) (*FilterResult, int, error) {
	result := &FilterResult{
		Joins:      []string{},
		Conditions: []string{},
	}

	pathIdx := startPathIdx

	paths := fg.graph.FindPathsBetween(rule.QualifiedEntityType(), targetEntityType, action, 10)

	for _, path := range paths {
		if !fg.pathAllowedByRule(rule, path, action) {
			continue
		}
		pathResult, err := fg.buildPathFilterWildcard(rule.QualifiedEntityType(), path, pathIdx)
		if err != nil {
			return nil, pathIdx, err
		}
		if len(pathResult.Conditions) > 0 || len(pathResult.Joins) > 0 {
			result.Joins = append(result.Joins, pathResult.Joins...)
			result.Conditions = append(result.Conditions, pathResult.Conditions...)
			pathIdx++
		}
	}

	return result, pathIdx, nil
}

// pathAllowedByRule checks if a graph path is allowed by a specific rule's relations
func (fg *FilterGenerator) pathAllowedByRule(rule *models.Rule, path []*GraphEdge, action string) bool {
	if len(path) == 0 {
		return false
	}

	currentRelations := rule.Relations
	for i, edge := range path {
		found := false
		for _, rel := range currentRelations {
			if rel.QualifiedTo() == edge.To && rel.Via == edge.Via {
				if i == len(path)-1 {
					if !relHasAction(&rel, action) {
						return false
					}
				}
				currentRelations = rel.Relations
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// relHasAction checks if a models.RelationRule supports an action
func relHasAction(rel *models.RelationRule, action string) bool {
	return rel.HasAction(action)
}

// buildPathFilter converts a graph path into JOIN clauses and WHERE conditions
func (fg *FilterGenerator) buildPathFilter(ownedEntityType string, ownedEntityID string, path []*GraphEdge, pathIdx int) (*FilterResult, error) {
	if len(path) == 0 {
		return &FilterResult{}, nil
	}

	if path[0].From != ownedEntityType {
		return nil, fmt.Errorf("path does not start from owned entity %s", ownedEntityType)
	}

	targetSchema, err := fg.schemas.Get(path[len(path)-1].To)
	if err != nil {
		return nil, err
	}

	result := &FilterResult{
		Joins:      []string{},
		Conditions: []string{},
	}

	var ownedSchema *SchemaDefinition
	var ownedAlias string
	for i := len(path) - 1; i >= 0; i-- {
		edge := path[i]
		joinIdx := len(path) - 1 - i
		alias := fmt.Sprintf("j%d_%d", pathIdx, joinIdx)

		if joinIdx == 0 {
			fromSchema, err := fg.schemas.Get(edge.From)
			if err != nil {
				return nil, fmt.Errorf("schema not found for entity %s: %w", edge.From, err)
			}

			joinClause := fmt.Sprintf("LEFT JOIN %s AS %s ON %s.%s = %s.%s",
				fromSchema.QualifiedTableName(),
				alias,
				targetSchema.QualifiedTableName(),
				edge.ForeignKey,
				alias,
				fromSchema.PrimaryKeys[0])
			result.Joins = append(result.Joins, joinClause)
		} else {
			prevAlias := fmt.Sprintf("j%d_%d", pathIdx, joinIdx-1)
			fromSchema, err := fg.schemas.Get(edge.From)
			if err != nil {
				return nil, fmt.Errorf("schema not found for entity %s: %w", edge.From, err)
			}

			joinClause := fmt.Sprintf("LEFT JOIN %s AS %s ON %s.%s = %s.%s",
				fromSchema.QualifiedTableName(),
				alias,
				prevAlias,
				edge.ForeignKey,
				alias,
				fromSchema.PrimaryKeys[0])
			result.Joins = append(result.Joins, joinClause)
		}

		if edge.From == ownedEntityType {
			ownedSchema, err = fg.schemas.Get(edge.From)
			if err != nil {
				return nil, fmt.Errorf("schema not found for owned entity %s: %w", edge.From, err)
			}
			ownedAlias = alias
		}
	}

	if ownedSchema == nil || ownedAlias == "" {
		return nil, fmt.Errorf("owned entity alias not found in path for %s", ownedEntityType)
	}

	result.Conditions = append(result.Conditions, fmt.Sprintf("%s.%s = %s", ownedAlias, ownedSchema.PrimaryKeys[0], sqlStringLiteral(ownedEntityID)))
	result.buildFullSQL(targetSchema, " AND ")

	return result, nil
}

// buildPathFilterByColumnFilter converts a graph path into JOIN clauses with column-filter conditions
func (fg *FilterGenerator) buildPathFilterByColumnFilter(ownedEntityType string, columnFilters []models.ColumnFilter, path []*GraphEdge, pathIdx int) (*FilterResult, error) {
	if len(path) == 0 {
		return &FilterResult{}, nil
	}

	if path[0].From != ownedEntityType {
		return nil, fmt.Errorf("path does not start from owned entity %s", ownedEntityType)
	}

	targetSchema, err := fg.schemas.Get(path[len(path)-1].To)
	if err != nil {
		return nil, err
	}

	result := &FilterResult{
		Joins:      []string{},
		Conditions: []string{},
	}

	for i := len(path) - 1; i >= 0; i-- {
		edge := path[i]
		joinIdx := len(path) - 1 - i
		alias := fmt.Sprintf("j%d_%d", pathIdx, joinIdx)

		if joinIdx == 0 {
			fromSchema, err := fg.schemas.Get(edge.From)
			if err != nil {
				return nil, fmt.Errorf("schema not found for entity %s: %w", edge.From, err)
			}
			joinClause := fmt.Sprintf("LEFT JOIN %s AS %s ON %s.%s = %s.%s",
				fromSchema.QualifiedTableName(),
				alias,
				targetSchema.QualifiedTableName(),
				edge.ForeignKey,
				alias,
				fromSchema.PrimaryKeys[0])
			result.Joins = append(result.Joins, joinClause)
		} else {
			prevAlias := fmt.Sprintf("j%d_%d", pathIdx, joinIdx-1)
			fromSchema, err := fg.schemas.Get(edge.From)
			if err != nil {
				return nil, fmt.Errorf("schema not found for entity %s: %w", edge.From, err)
			}
			joinClause := fmt.Sprintf("LEFT JOIN %s AS %s ON %s.%s = %s.%s",
				fromSchema.QualifiedTableName(),
				alias,
				prevAlias,
				edge.ForeignKey,
				alias,
				fromSchema.PrimaryKeys[0])
			result.Joins = append(result.Joins, joinClause)
		}
	}

	ownedAlias := fmt.Sprintf("j%d_%d", pathIdx, len(path)-1)
	ownedSchema, err := fg.schemas.Get(ownedEntityType)
	if err != nil {
		return nil, fmt.Errorf("schema not found for owned entity %s: %w", ownedEntityType, err)
	}

	cond, err := buildColumnFilterConditionsWithPrefix(ownedSchema, columnFilters, ownedAlias)
	if err != nil {
		return nil, fmt.Errorf("column filter error for cascading entity %s: %w", ownedEntityType, err)
	}
	if cond != "" {
		result.Conditions = append(result.Conditions, cond)
	} else {
		result.Conditions = append(result.Conditions, fmt.Sprintf("%s.%s IS NOT NULL", ownedAlias, ownedSchema.PrimaryKeys[0]))
	}

	result.buildFullSQL(targetSchema, " AND ")

	return result, nil
}

// buildCascadingAccessByColumnFilter builds cascading access from entities satisfying column filters
func (fg *FilterGenerator) buildCascadingAccessByColumnFilter(rule *models.Rule, action string, targetEntityType string, startPathIdx int) (*FilterResult, int, error) {
	result := &FilterResult{
		Joins:      []string{},
		Conditions: []string{},
	}

	pathIdx := startPathIdx

	paths := fg.graph.FindPathsBetween(rule.QualifiedEntityType(), targetEntityType, action, 10)

	for _, path := range paths {
		if !fg.pathAllowedByRule(rule, path, action) {
			continue
		}
		pathResult, err := fg.buildPathFilterByColumnFilter(rule.QualifiedEntityType(), rule.ColumnFilters, path, pathIdx)
		if err != nil {
			return nil, pathIdx, err
		}
		if len(pathResult.Conditions) > 0 || len(pathResult.Joins) > 0 {
			result.Joins = append(result.Joins, pathResult.Joins...)
			result.Conditions = append(result.Conditions, pathResult.Conditions...)
			pathIdx++
		}
	}

	return result, pathIdx, nil
}

// buildPathFilterWildcard converts a graph path into JOIN clauses for wildcard (all entities)
func (fg *FilterGenerator) buildPathFilterWildcard(ownedEntityType string, path []*GraphEdge, pathIdx int) (*FilterResult, error) {
	if len(path) == 0 {
		return &FilterResult{}, nil
	}

	if path[0].From != ownedEntityType {
		return nil, fmt.Errorf("path does not start from owned entity %s", ownedEntityType)
	}

	targetSchema, err := fg.schemas.Get(path[len(path)-1].To)
	if err != nil {
		return nil, err
	}

	result := &FilterResult{
		Joins:      []string{},
		Conditions: []string{},
	}

	for i := len(path) - 1; i >= 0; i-- {
		edge := path[i]
		joinIdx := len(path) - 1 - i
		alias := fmt.Sprintf("j%d_%d", pathIdx, joinIdx)

		if joinIdx == 0 {
			fromSchema, err := fg.schemas.Get(edge.From)
			if err != nil {
				return nil, fmt.Errorf("schema not found for entity %s: %w", edge.From, err)
			}

			joinClause := fmt.Sprintf("LEFT JOIN %s AS %s ON %s.%s = %s.%s",
				fromSchema.QualifiedTableName(),
				alias,
				targetSchema.QualifiedTableName(),
				edge.ForeignKey,
				alias,
				fromSchema.PrimaryKeys[0])
			result.Joins = append(result.Joins, joinClause)
		} else {
			prevAlias := fmt.Sprintf("j%d_%d", pathIdx, joinIdx-1)
			fromSchema, err := fg.schemas.Get(edge.From)
			if err != nil {
				return nil, fmt.Errorf("schema not found for entity %s: %w", edge.From, err)
			}

			joinClause := fmt.Sprintf("LEFT JOIN %s AS %s ON %s.%s = %s.%s",
				fromSchema.QualifiedTableName(),
				alias,
				prevAlias,
				edge.ForeignKey,
				alias,
				fromSchema.PrimaryKeys[0])
			result.Joins = append(result.Joins, joinClause)
		}
	}

	// Add a condition that the join chain is valid (owned entity exists).
	lastAlias := fmt.Sprintf("j%d_%d", pathIdx, len(path)-1)
	ownedEntityType = path[0].From
	var ownedSchema *SchemaDefinition
	ownedSchema, err = fg.schemas.Get(ownedEntityType)
	if err != nil {
		return nil, fmt.Errorf("schema not found for owned entity %s: %w", ownedEntityType, err)
	}
	result.Conditions = append(result.Conditions, fmt.Sprintf("%s.%s IS NOT NULL", lastAlias, ownedSchema.PrimaryKeys[0]))

	result.buildFullSQL(targetSchema, " AND ")

	return result, nil
}
