package authz

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
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
func (e *Engine) GetGlobalCapabilities(policies *PolicyRegistry) (GlobalCapabilities, error) {
	result := make(GlobalCapabilities)

	allSchemas := e.schemas.GetAll()
	for _, schema := range allSchemas {
		namespacedKey := schema.NamespacedType()
		for _, action := range schema.GlobalActions {
			for _, policy := range policies.GetAll() {
				for _, rule := range policy.Rules {
					if ruleMatchesSchema(rule, schema) && rule.HasAction(action) {
						result.addGlobalAction(namespacedKey, action)
						log.Printf("[CAPABILITIES] Global action '%s' on '%s' granted by policy '%s'",
							action, namespacedKey, policy.ID)
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
	policies *PolicyRegistry,
	namespace, schemaName, entityType string, entityKey map[string]string,
) (*EntityCapabilities, error) {
	schema, err := e.schemas.GetBySchemaEntity(schemaName, entityType)
	if err != nil {
		return nil, fmt.Errorf("schema not found for %s.%s: %w", schemaName, entityType, err)
	}
	if schema.ConfigSchema != namespace {
		return nil, fmt.Errorf("entity type '%s.%s' does not belong to namespace '%s'", schemaName, entityType, namespace)
	}

	result := &EntityCapabilities{
		Namespace:  namespace,
		SchemaName: schemaName,
		EntityType: entityType,
		EntityKey:  entityKey,
		Actions:    []string{},
	}

	for _, action := range schema.AtomicActions {
		allowed, err := e.Authorize(policies, schema.ConfigSchema, schemaName, action, entityType, entityKey)
		if err != nil {
			log.Printf("[CAPABILITIES] Warning: auth check failed for action=%s entity=%s.%s/%v: %v",
				action, schemaName, entityType, entityKey, err)
			continue
		}
		if allowed {
			result.Actions = append(result.Actions, action)
		}
	}

	log.Printf("[CAPABILITIES] Entity %s.%s/%v: atomic actions granted = %v",
		schemaName, entityType, entityKey, result.Actions)

	return result, nil
}

// GetPrincipalPolicies retrieves all policies associated with a principal from the database
// and returns them as a ready-to-use PolicyRegistry.
func (e *Engine) GetPrincipalPolicies(
	principalManager *PrincipalManager,
	policyManager *PolicyManager,
	principalID string,
) (*PolicyRegistry, error) {
	principal, err := principalManager.GetPrincipalWithPolicies(principalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal: %w", err)
	}

	registry := NewPolicyRegistry()
	for _, pp := range principal.Policies {
		policy, err := policyManager.GetPolicy(context.Background(), pp.PolicyID)
		if err != nil {
			log.Printf("[CAPABILITIES] Warning: could not load policy %s: %v", pp.PolicyID, err)
			continue
		}
		if err := registry.AddPolicy(policy); err != nil {
			log.Printf("[CAPABILITIES] Warning: could not add policy %s to registry: %v", pp.PolicyID, err)
			continue
		}
	}

	return registry, nil
}

// GetGlobalCapabilitiesForPrincipal loads the principal's policies and returns their global
// capabilities across all entity types.
func (e *Engine) GetGlobalCapabilitiesForPrincipal(
	principalManager *PrincipalManager,
	policyManager *PolicyManager,
	principalID string,
) (GlobalCapabilities, error) {
	policies, err := e.GetPrincipalPolicies(principalManager, policyManager, principalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal policies: %w", err)
	}
	return e.GetGlobalCapabilities(policies)
}

// GetEntityCapabilitiesForPrincipal loads the principal's policies and returns the atomic
// actions granted on the specified entity instance.
func (e *Engine) GetEntityCapabilitiesForPrincipal(
	principalManager *PrincipalManager,
	policyManager *PolicyManager,
	principalID, namespace, schemaName, entityType string, entityKey map[string]string,
) (*EntityCapabilities, error) {
	policies, err := e.GetPrincipalPolicies(principalManager, policyManager, principalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal policies: %w", err)
	}
	return e.GetEntityCapabilities(policies, namespace, schemaName, entityType, entityKey)
}

// EntityCapabilityQuery describes a single entity to evaluate in a batch request.
type EntityCapabilityQuery struct {
	Namespace  string            `json:"namespace"`
	SchemaName string            `json:"schema_name"`
	EntityType string            `json:"entity_type"`
	EntityKey  map[string]string `json:"entity_key"`
}

// GetEntityCapabilitiesBatch evaluates a slice of entity queries against the same
// PolicyRegistry in a single call, loading the principal's policies only once.
// Results are returned in the same order as the input queries.
// If a query fails (e.g. unknown schema/namespace mismatch) its entry will have an empty
// Actions slice and a non-nil Error field.
type EntityCapabilitiesResult struct {
	EntityCapabilities
	Error string `json:"error,omitempty"`
}

func (e *Engine) GetEntityCapabilitiesBatch(
	policies *PolicyRegistry,
	queries []EntityCapabilityQuery,
) []EntityCapabilitiesResult {
	results := make([]EntityCapabilitiesResult, len(queries))
	for i, q := range queries {
		ec, err := e.GetEntityCapabilities(policies, q.Namespace, q.SchemaName, q.EntityType, q.EntityKey)
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

// GetEntityCapabilitiesBatchForPrincipal loads the principal's policies once and evaluates
// all queries, returning results in the same order as the input.
func (e *Engine) GetEntityCapabilitiesBatchForPrincipal(
	principalManager *PrincipalManager,
	policyManager *PolicyManager,
	principalID string,
	queries []EntityCapabilityQuery,
) ([]EntityCapabilitiesResult, error) {
	policies, err := e.GetPrincipalPolicies(principalManager, policyManager, principalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal policies: %w", err)
	}
	return e.GetEntityCapabilitiesBatch(policies, queries), nil
}

// parseCertificate parses a PEM- or DER-encoded X.509 certificate.
func parseCertificate(certPEM string) (*x509.Certificate, error) {
	if strings.Contains(certPEM, "BEGIN CERTIFICATE") {
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block")
		}
		return x509.ParseCertificate(block.Bytes)
	}
	return x509.ParseCertificate([]byte(certPEM))
}
