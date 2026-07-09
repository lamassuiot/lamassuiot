package engine

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/sirupsen/logrus"
)

// GlobalCapabilities maps a namespaced entity type key ("namespace.schema_name.entity_type",
// e.g. "iot.public.device") to the list of global actions the principal is granted on that
// type (e.g. ["create", "list"]).  Atomic actions are never present here.
type GlobalCapabilities map[string][]string

// EntityCapabilities holds the atomic actions granted to a principal on one concrete entity
// instance.  Global actions are never present here.
type EntityCapabilities struct {
	Namespace  string            `json:"namespace"`
	SchemaName string            `json:"schema_name"`
	EntityType string            `json:"entity_type"`
	EntityKey  map[string]string `json:"entity_key"`
	Actions    []string          `json:"actions"`
}

// EntityCapabilityQuery describes a single entity to evaluate in a batch request.
type EntityCapabilityQuery struct {
	Namespace  string            `json:"namespace"`
	SchemaName string            `json:"schema_name"`
	EntityType string            `json:"entity_type"`
	EntityKey  map[string]string `json:"entity_key"`
}

// EntityCapabilitiesResult wraps EntityCapabilities with an optional error string so that
// one failed batch entry does not abort the whole response.
type EntityCapabilitiesResult struct {
	EntityCapabilities
	Error string `json:"error,omitempty"`
}

// addGlobalAction merges a single global action into the GlobalCapabilities map (deduplicates).
func (gc GlobalCapabilities) addGlobalAction(qualifiedEntityType, action string) {
	for _, a := range gc[qualifiedEntityType] {
		if a == action {
			return
		}
	}
	gc[qualifiedEntityType] = append(gc[qualifiedEntityType], action)
}

// MergeGlobalCapabilities merges src into dst using OR logic (union of actions).
func MergeGlobalCapabilities(dst, src GlobalCapabilities) {
	for entityType, actions := range src {
		for _, action := range actions {
			dst.addGlobalAction(entityType, action)
		}
	}
}

// GetGlobalCapabilities evaluates the given policies and returns every global action
// (those classified as globalActions in the schema) the principal is granted, grouped by
// qualified entity type (e.g. "public.device").  Atomic actions are never included.
func (e *Engine) GetGlobalCapabilities(ctx context.Context, policies *PolicyRegistry) (GlobalCapabilities, error) {
	log := helpers.ConfigureLogger(ctx, e.logger)
	result := make(GlobalCapabilities)

	allSchemas := e.schemas.GetAll()
	for _, schema := range allSchemas {
		namespacedKey := schema.NamespacedType()
		for _, action := range schema.GlobalActions {
			for _, policy := range policies.GetAll() {
				for _, rule := range policy.Rules {
					if ruleMatchesSchema(rule, schema) && rule.HasAction(action) {
						result.addGlobalAction(namespacedKey, action)
						log.WithFields(logrus.Fields{
							"action":      action,
							"entity_type": namespacedKey,
							"policy_id":   policy.ID,
						}).Debug("global action granted")
						break
					}
				}
			}
		}
	}

	return result, nil
}

// GetEntityCapabilities evaluates the given policies against a specific entity instance and
// returns only the atomic actions (those classified as atomicActions in the schema) that are
// granted on that entity.  Global actions are never included.
func (e *Engine) GetEntityCapabilities(
	ctx context.Context,
	policies *PolicyRegistry,
	namespace, schemaName, entityType string, entityKey map[string]string,
) (*EntityCapabilities, error) {
	schema, err := e.schemas.GetBySchemaEntity(schemaName, entityType)
	if err != nil {
		return nil, err
	}

	result := &EntityCapabilities{
		Namespace:  namespace,
		SchemaName: schemaName,
		EntityType: entityType,
		EntityKey:  entityKey,
		Actions:    []string{},
	}

	for _, action := range schema.AtomicActions {
		allowed, err := e.Authorize(ctx, policies, namespace, schemaName, action, entityType, entityKey)
		if err != nil {
			continue
		}
		if allowed {
			result.Actions = append(result.Actions, action)
		}
	}

	return result, nil
}

// GetEntityCapabilitiesBatch evaluates a slice of entity queries against the same
// PolicyRegistry in a single call, loading the principal's policies only once.
// Results are returned in the same order as the input queries.
func (e *Engine) GetEntityCapabilitiesBatch(
	ctx context.Context,
	policies *PolicyRegistry,
	queries []EntityCapabilityQuery,
) []EntityCapabilitiesResult {
	results := make([]EntityCapabilitiesResult, len(queries))
	for i, q := range queries {
		ec, err := e.GetEntityCapabilities(ctx, policies, q.Namespace, q.SchemaName, q.EntityType, q.EntityKey)
		if err != nil {
			results[i] = EntityCapabilitiesResult{
				EntityCapabilities: EntityCapabilities{
					Namespace:  q.Namespace,
					SchemaName: q.SchemaName,
					EntityType: q.EntityType,
					EntityKey:  q.EntityKey,
					Actions:    []string{},
				},
				Error: err.Error(),
			}
		} else {
			results[i] = EntityCapabilitiesResult{EntityCapabilities: *ec}
		}
	}
	return results
}
