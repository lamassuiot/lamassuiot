package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
)

// PolicyRegistry manages all authorization policies
type PolicyRegistry struct {
	policies []*models.Policy
}

// NewPolicyRegistry creates a new policy registry
func NewPolicyRegistry() *PolicyRegistry {
	return &PolicyRegistry{
		policies: make([]*models.Policy, 0),
	}
}

// AddPolicy adds a policy to the registry after validation
func (r *PolicyRegistry) AddPolicy(policy *models.Policy) error {
	if err := r.validatePolicy(policy); err != nil {
		return fmt.Errorf("invalid policy %s: %w", policy.ID, err)
	}
	r.policies = append(r.policies, policy)
	return nil
}

// Load reads and parses policies from a JSON file
func (r *PolicyRegistry) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read policy file %s: %w", path, err)
	}

	var policies []models.Policy
	if err := json.Unmarshal(data, &policies); err != nil {
		return fmt.Errorf("failed to parse policy JSON: %w", err)
	}

	if len(policies) == 0 {
		return nil
	}

	for i := range policies {
		policy := &policies[i]
		if err := r.validatePolicy(policy); err != nil {
			return fmt.Errorf("invalid policy %s: %w", policy.ID, err)
		}
		r.policies = append(r.policies, policy)
	}

	return nil
}

// Get retrieves the first rule by entity type across all policies
func (r *PolicyRegistry) Get(entityType string) (*models.Rule, error) {
	for _, policy := range r.policies {
		for _, rule := range policy.Rules {
			if rule.QualifiedEntityType() == entityType {
				return rule, nil
			}
		}
	}
	return nil, fmt.Errorf("rule not found for entity type: %s", entityType)
}

// GetByID retrieves a policy by its unique ID
func (r *PolicyRegistry) GetByID(policyID string) (*models.Policy, error) {
	for _, policy := range r.policies {
		if policy.ID == policyID {
			return policy, nil
		}
	}
	return nil, fmt.Errorf("policy not found with ID: %s", policyID)
}

// GetAll returns all registered policies as a slice
func (r *PolicyRegistry) GetAll() []*models.Policy {
	return r.policies
}

func (r *PolicyRegistry) validatePolicy(policy *models.Policy) error {
	return ValidatePolicyStruct(policy)
}

func (r *PolicyRegistry) validateRule(rule *models.Rule) error {
	return validateRuleStruct(rule)
}

// ValidatePolicyStruct validates a policy structure.
// Exported so the service layer can reuse it for storage-time validation.
// A policy must contain at least one Rule or one HTTPRule (or both).
func ValidatePolicyStruct(policy *models.Policy) error {
	if policy.ID == "" {
		return fmt.Errorf("policy ID is required")
	}

	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}

	if len(policy.Rules) == 0 && len(policy.HTTPRules) == 0 {
		return fmt.Errorf("policy must contain at least one rule or http_rule")
	}

	for i, rule := range policy.Rules {
		if err := validateRuleStruct(rule); err != nil {
			return fmt.Errorf("invalid rule at index %d: %w", i, err)
		}
	}

	for i, hr := range policy.HTTPRules {
		if err := validateHTTPRuleStruct(hr); err != nil {
			return fmt.Errorf("invalid http_rule at index %d: %w", i, err)
		}
	}

	return nil
}

func validateHTTPRuleStruct(r *models.HTTPRule) error {
	if r.SchemaName == "" {
		return fmt.Errorf("http_schema_name is required")
	}
	if len(r.Actions) == 0 {
		return fmt.Errorf("actions must not be empty; use [\"*\"] to grant all")
	}
	for i, pc := range r.ParamConstraints {
		if pc.Action == "" {
			return fmt.Errorf("param_constraints[%d]: action is required", i)
		}
		if !r.HasHTTPAction(pc.Action) {
			return fmt.Errorf("param_constraints[%d]: action %q must also be listed in actions", i, pc.Action)
		}
		if pc.Equals == "" {
			return fmt.Errorf("param_constraints[%d]: equals is required", i)
		}
		switch pc.Request.Source {
		case "path_regex_group":
			if pc.Request.Index <= 0 {
				return fmt.Errorf("param_constraints[%d]: path_regex_group index must be greater than zero", i)
			}
		case "query", "header":
			if pc.Request.Name == "" {
				return fmt.Errorf("param_constraints[%d]: %s name is required", i, pc.Request.Source)
			}
		case "json_body":
			if pc.Request.Path == "" {
				return fmt.Errorf("param_constraints[%d]: json_body path is required", i)
			}
		default:
			return fmt.Errorf("param_constraints[%d]: unsupported request source %q", i, pc.Request.Source)
		}
	}
	return nil
}

func validateRuleStruct(rule *models.Rule) error {
	if rule.Namespace == "" {
		return fmt.Errorf("namespace is required")
	}

	if rule.SchemaName == "" {
		return fmt.Errorf("schemaName is required")
	}

	if rule.EntityType == "" {
		return fmt.Errorf("entityType is required")
	}

	if rule.SchemaName != "*" && strings.Contains(rule.SchemaName, ".") {
		return fmt.Errorf("schemaName must be unqualified or wildcard '*'")
	}

	if rule.EntityType != "*" && strings.Contains(rule.EntityType, ".") {
		return fmt.Errorf("entityType must be unqualified; use schemaName + entityType")
	}

	qualifiedEntityType := rule.QualifiedEntityType()
	if qualifiedEntityType == "" || !strings.Contains(qualifiedEntityType, ".") {
		return fmt.Errorf("entityType must be provided as schemaName + entityType, got: schemaName=%s entityType=%s", rule.SchemaName, rule.EntityType)
	}

	if len(rule.Actions) == 0 && len(rule.Relations) == 0 && len(rule.DirectGrants) == 0 && len(rule.ColumnFilters) == 0 {
		return fmt.Errorf("rule must define actions, relations, direct grants, or column filters")
	}

	validOperators := map[string]bool{"eq": true, "neq": true, "gt": true, "gte": true, "lt": true, "lte": true, "in": true, "like": true}
	for i, cf := range rule.ColumnFilters {
		if cf.Column == "" {
			return fmt.Errorf("column filter at index %d: column is required", i)
		}
		if !validOperators[cf.Operator] {
			return fmt.Errorf("column filter %q: unsupported operator %q (must be eq, neq, gt, gte, lt, lte, in, or like)", cf.Column, cf.Operator)
		}
		if cf.Value == nil {
			return fmt.Errorf("column filter %q: value is required", cf.Column)
		}
	}

	for i := range rule.Relations {
		if err := validateRelationRuleStruct(&rule.Relations[i], 0); err != nil {
			return fmt.Errorf("invalid relation rule at index %d: %w", i, err)
		}
	}

	if err := validateSimpleRelationPaths(rule); err != nil {
		return err
	}

	return nil
}

func validateSimpleRelationPaths(rule *models.Rule) error {
	start := rule.QualifiedEntityType()
	visited := map[string]bool{start: true}
	path := []string{start}

	for i := range rule.Relations {
		if err := validateSimpleRelationPathRecursive(&rule.Relations[i], visited, path); err != nil {
			return fmt.Errorf("invalid relation path at index %d: %w", i, err)
		}
	}

	return nil
}

func validateSimpleRelationPathRecursive(rel *models.RelationRule, visited map[string]bool, path []string) error {
	target := rel.QualifiedTo()
	if target == "" {
		return nil
	}

	if visited[target] {
		fullPath := append(append([]string{}, path...), target)
		return fmt.Errorf("relation path must be simple (no repeated vertices), repeated entity '%s' in path %s", target, strings.Join(fullPath, " -> "))
	}

	visited[target] = true
	nextPath := append(path, target)
	for i := range rel.Relations {
		if err := validateSimpleRelationPathRecursive(&rel.Relations[i], visited, nextPath); err != nil {
			return fmt.Errorf("nested relation at index %d: %w", i, err)
		}
	}
	delete(visited, target)

	return nil
}

func (r *PolicyRegistry) validateRelationRule(rel *models.RelationRule, parentNamespace string, depth int) error {
	_ = parentNamespace
	return validateRelationRuleStruct(rel, depth)
}

func validateRelationRuleStruct(rel *models.RelationRule, depth int) error {
	if depth > 10 {
		return fmt.Errorf("relation nesting depth exceeds maximum of 10")
	}

	if rel.To == "" {
		if rel.ToEntityType == "" {
			return fmt.Errorf("'to' field is required in relation rule")
		}
	}

	if rel.ToSchemaName == "" || rel.ToEntityType == "" {
		return fmt.Errorf("relation 'to' must be an object with schemaName and entityType")
	}

	if strings.Contains(rel.ToSchemaName, "*") {
		return fmt.Errorf("wildcards are not supported in relation 'to.schemaName'")
	}

	if strings.Contains(rel.ToEntityType, "*") {
		return fmt.Errorf("wildcards are not supported in relation 'to.entityType'")
	}

	if strings.Contains(rel.Via, "*") {
		return fmt.Errorf("wildcards are not supported in relation 'via'")
	}

	if strings.Contains(rel.ToEntityType, ".") {
		return fmt.Errorf("relation 'to.entityType' must be unqualified; use to.schemaName + to.entityType")
	}

	relationTarget := rel.QualifiedTo()
	if relationTarget == "" || !strings.Contains(relationTarget, ".") {
		return fmt.Errorf("relation 'to' must be provided as to.schemaName + to.entityType")
	}
	if rel.Via == "" {
		return fmt.Errorf("'via' field is required in relation rule")
	}
	if len(rel.Actions) == 0 {
		return fmt.Errorf("at least one action must be defined in relation rule")
	}

	for i := range rel.Relations {
		if err := validateRelationRuleStruct(&rel.Relations[i], depth+1); err != nil {
			return fmt.Errorf("invalid nested relation at index %d: %w", i, err)
		}
	}

	return nil
}

// GetRules returns all rules across all policies
func (r *PolicyRegistry) GetRules() []*models.Rule {
	var rules []*models.Rule
	for _, policy := range r.policies {
		rules = append(rules, policy.Rules...)
	}
	return rules
}

func wildcardMatches(pattern, value string) bool {
	return pattern == "*" || pattern == value
}

func ruleMatchesSchema(rule *models.Rule, schema *SchemaDefinition) bool {
	if rule.Namespace != schema.ConfigSchema {
		return false
	}

	if !wildcardMatches(rule.SchemaName, schema.SchemaName) {
		return false
	}

	if !wildcardMatches(rule.EntityType, schema.EntityType) {
		return false
	}

	return true
}

func concretizeRuleForSchema(rule *models.Rule, schema *SchemaDefinition) *models.Rule {
	concrete := *rule
	concrete.SchemaName = schema.SchemaName
	concrete.EntityType = schema.EntityType
	return &concrete
}

// ErrPolicySchemaMismatch wraps every reason ValidatePolicyAgainstSchemas rejects a policy, so
// callers can report all of them as invalid input.
var ErrPolicySchemaMismatch = errors.New("policy does not match the loaded schemas")

// ValidatePolicyAgainstSchemas rejects, when the policy is saved, the relations that the graph
// would skip at evaluation time (an undeclared via grants nothing) or fail on (an unloaded relation
// target fails the whole authorization). Rules are concretized like buildPolicyEdges does:
//   - every relation target must be a loaded schema in the rule's namespace;
//   - a via must resolve from at least one schema the rule matches, since a wildcard rule
//     legitimately resolves it for some matches and not for others;
//   - a non-wildcard rule with relations must match a loaded schema.
//
// A wildcard rule that matches no schema is skipped at evaluation time with a warning, so it is not
// rejected here.
func ValidatePolicyAgainstSchemas(policy *models.Policy, schemas *SchemaRegistry) error {
	for i, rule := range policy.Rules {
		if len(rule.Relations) == 0 {
			continue
		}
		var fromEntities []string
		for _, schema := range schemas.GetAll() {
			if ruleMatchesSchema(rule, schema) {
				fromEntities = append(fromEntities, schema.QualifiedEntityType())
			}
		}
		if len(fromEntities) == 0 {
			if rule.SchemaName == "*" || rule.EntityType == "*" {
				continue
			}
			return fmt.Errorf("%w: invalid rule at index %d: %s is not a loaded schema in namespace %s",
				ErrPolicySchemaMismatch, i, rule.QualifiedEntityType(), rule.Namespace)
		}
		if err := validateRelationsAgainstSchemas(fromEntities, rule.Namespace, rule.Relations, schemas); err != nil {
			return fmt.Errorf("%w: invalid rule at index %d: %w", ErrPolicySchemaMismatch, i, err)
		}
	}
	return nil
}

func validateRelationsAgainstSchemas(fromEntities []string, namespace string, relations []models.RelationRule, schemas *SchemaRegistry) error {
	for i := range relations {
		rel := &relations[i]
		target := rel.QualifiedTo()
		targetSchema := findSchemaForRelation(namespace, target, schemas)
		if targetSchema == nil {
			return fmt.Errorf("relation target %s is not a loaded schema in namespace %s", target, namespace)
		}
		if err := resolveFromAny(fromEntities, namespace, rel.Via, targetSchema, schemas); err != nil {
			return err
		}
		if err := validateRelationsAgainstSchemas([]string{target}, namespace, rel.Relations, schemas); err != nil {
			return err
		}
	}
	return nil
}

func resolveFromAny(fromEntities []string, namespace, via string, targetSchema *SchemaDefinition, schemas *SchemaRegistry) error {
	var err error
	for _, from := range fromEntities {
		if _, err = resolveRelationForeignKey(from, namespace, via, targetSchema, schemas); err == nil {
			return nil
		}
	}
	if len(fromEntities) > 1 && errors.Is(err, ErrUndeclaredVia) {
		return fmt.Errorf("%w: %q towards %s from any schema the rule matches", ErrUndeclaredVia, via, targetSchema.QualifiedEntityType())
	}
	return err
}
