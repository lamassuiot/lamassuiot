package authz

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/lamassuiot/authz/pkg/models"
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

	// Allow empty policy arrays (0 policies)
	if len(policies) == 0 {
		return nil
	}

	// Validate and register policies
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

// validatePolicy checks if a policy definition is valid
func (r *PolicyRegistry) validatePolicy(policy *models.Policy) error {
	return validatePolicyStruct(policy)
}

// validateRule checks if a rule definition is valid
func (r *PolicyRegistry) validateRule(rule *models.Rule) error {
	return validateRuleStruct(rule)
}

// validatePolicyStruct validates a policy structure.
// Shared across policy registry and policy manager flows.
func validatePolicyStruct(policy *models.Policy) error {
	if policy.ID == "" {
		return fmt.Errorf("policy ID is required")
	}

	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}

	if len(policy.Rules) == 0 {
		return fmt.Errorf("policy must contain at least one rule")
	}

	for i, rule := range policy.Rules {
		if err := validateRuleStruct(rule); err != nil {
			return fmt.Errorf("invalid rule at index %d: %w", i, err)
		}
	}

	return nil
}

// validateRuleStruct validates a rule structure.
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

	// Validate direct actions
	if len(rule.Actions) == 0 && len(rule.Relations) == 0 && len(rule.DirectGrants) == 0 && len(rule.ColumnFilters) == 0 {
		return fmt.Errorf("rule must define actions, relations, direct grants, or column filters")
	}

	// Validate column filters
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

	// Validate relation rules
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

// validateRelationRule validates a relation rule recursively
func (r *PolicyRegistry) validateRelationRule(rel *models.RelationRule, parentNamespace string, depth int) error {
	_ = parentNamespace
	return validateRelationRuleStruct(rel, depth)
}

// validateRelationRuleStruct validates a relation rule recursively.
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

	// Recursively validate nested relations - they use the same namespace
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
