package models

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ColumnFilter specifies a column-value condition that scopes rule access.
// It is the attribute-based counterpart to DirectGrants: instead of granting
// access to specific entity IDs, it grants access to all entities where the
// declared column satisfies the condition.
type ColumnFilter struct {
	Column   string      `json:"column"`
	Type     string      `json:"type,omitempty"` // optional: string, int, float, bool, timestamp, jsonb — must match the schema's filterable declaration when provided
	Operator string      `json:"operator"`       // eq, neq, gt, gte, lt, lte, in, like
	Value    interface{} `json:"value"`
}

// Rule defines authorization rules for an entity type
type Rule struct {
	Namespace     string         `json:"namespace"` // Namespace/config schema name (e.g., "iot", "pki")
	SchemaName    string         `json:"schemaName,omitempty"`
	EntityType    string         `json:"entityType"`
	Actions       []string       `json:"actions"`
	Relations     []RelationRule `json:"relations"`
	DirectGrants  []string       `json:"directGrants,omitempty"`  // IDs of this entityType that can be directly accessed
	ColumnFilters []ColumnFilter `json:"columnFilters,omitempty"` // Attribute-based conditions scoping access
}

// RelationRule defines cascading permissions through relations
// Relations always use the same namespace as their parent rule
type RelationRule struct {
	To           string         `json:"-"`
	ToSchemaName string         `json:"schemaName,omitempty"`
	ToEntityType string         `json:"entityType,omitempty"`
	Via          string         `json:"via"`
	Actions      []string       `json:"actions"`
	Relations    []RelationRule `json:"relations,omitempty"`
}

type relationTarget struct {
	SchemaName string `json:"schemaName,omitempty"`
	EntityType string `json:"entityType"`
}

func (r *RelationRule) UnmarshalJSON(data []byte) error {
	type relationRuleAlias struct {
		To        json.RawMessage `json:"to"`
		Via       string          `json:"via"`
		Actions   []string        `json:"actions"`
		Relations []RelationRule  `json:"relations,omitempty"`
	}

	var aux relationRuleAlias
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	r.Via = aux.Via
	r.Actions = aux.Actions
	r.Relations = aux.Relations

	if len(aux.To) == 0 || string(aux.To) == "null" {
		return nil
	}

	var targetObj relationTarget
	if err := json.Unmarshal(aux.To, &targetObj); err != nil {
		return fmt.Errorf("relation 'to' must be an object with schemaName and entityType: %w", err)
	}

	if targetObj.SchemaName == "" || targetObj.EntityType == "" {
		return fmt.Errorf("relation 'to' must include both schemaName and entityType")
	}

	r.ToSchemaName = targetObj.SchemaName
	r.ToEntityType = targetObj.EntityType
	r.To = QualifiedEntityType(targetObj.EntityType, targetObj.SchemaName)

	return nil
}

func (r RelationRule) MarshalJSON() ([]byte, error) {
	type relationRuleOut struct {
		To        interface{}    `json:"to"`
		Via       string         `json:"via"`
		Actions   []string       `json:"actions"`
		Relations []RelationRule `json:"relations,omitempty"`
	}

	var toValue interface{}
	if r.ToEntityType != "" || r.ToSchemaName != "" {
		toValue = relationTarget{
			SchemaName: r.ToSchemaName,
			EntityType: r.ToEntityType,
		}
	} else {
		toValue = r.To
	}

	return json.Marshal(relationRuleOut{
		To:        toValue,
		Via:       r.Via,
		Actions:   r.Actions,
		Relations: r.Relations,
	})
}

// Policy contains a collection of rules with metadata
type Policy struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Rules       []*Rule `json:"rules"`
}

// HasAction checks if a rule supports a specific action for direct access
func (r *Rule) HasAction(action string) bool {
	for _, a := range r.Actions {
		if a == "*" || a == action {
			return true
		}
	}
	return false
}

// QualifiedEntityType returns the fully qualified rule entity type
func (r *Rule) QualifiedEntityType() string {
	return QualifiedEntityType(r.EntityType, r.SchemaName)
}

// GetDirectGrants returns the list of directly granted entity IDs
func (r *Rule) GetDirectGrants() []string {
	return r.DirectGrants
}

// HasDirectGrants checks if direct grants are defined
func (r *Rule) HasDirectGrants() bool {
	return len(r.DirectGrants) > 0
}

// HasColumnFilters checks if column-filter conditions are defined
func (r *Rule) HasColumnFilters() bool {
	return len(r.ColumnFilters) > 0
}

// GetRelationsTo retrieves all relation rules targeting a specific entity type
func (r *Rule) GetRelationsTo(entityType string) []RelationRule {
	var result []RelationRule
	targetQualified := QualifiedEntityType(entityType, r.SchemaName)
	for _, rel := range r.Relations {
		relQualified := rel.QualifiedTo()
		if relQualified == entityType || relQualified == targetQualified || rel.To == entityType {
			result = append(result, rel)
		}
	}
	return result
}

// HasRelationAction checks if a relation rule supports a specific action
func (r *RelationRule) HasAction(action string) bool {
	for _, a := range r.Actions {
		if a == "*" || a == action {
			return true
		}
	}
	return false
}

// QualifiedTo returns the fully qualified relation target entity type
func (r *RelationRule) QualifiedTo() string {
	if r.To != "" {
		if strings.Contains(r.To, ".") {
			return r.To
		}
		if r.ToSchemaName != "" {
			return QualifiedEntityType(r.To, r.ToSchemaName)
		}
	}

	if r.ToEntityType != "" {
		return QualifiedEntityType(r.ToEntityType, r.ToSchemaName)
	}

	return ""
}

// GetSchemaAndEntity splits a potentially qualified entity type
// Returns (schemaName, entityType) from "schema.entity" or ("", entityType) from "entity"
func GetSchemaAndEntity(entityType string) (schema, entity string) {
	parts := strings.SplitN(entityType, ".", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", parts[0]
}

// QualifiedEntityType returns the fully qualified entity type with explicit schema
// If already qualified, returns as-is. If unqualified, prepends defaultSchema
func QualifiedEntityType(entityType, defaultSchema string) string {
	if strings.Contains(entityType, ".") {
		return entityType // Already qualified
	}
	if defaultSchema == "" {
		defaultSchema = "public"
	}
	return defaultSchema + "." + entityType
}
