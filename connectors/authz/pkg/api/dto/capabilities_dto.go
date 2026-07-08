package dto

// --- Global Capabilities ---

// GetGlobalCapabilitiesRequest is the request body for POST /api/v1/authz/capabilities/global.
type GetGlobalCapabilitiesRequest struct {
	PrincipalID string `json:"principal_id" binding:"required"`
}

// MatchAndGetGlobalCapabilitiesRequest is the request body for
// POST /api/v1/authz/match/capabilities/global.
type MatchAndGetGlobalCapabilitiesRequest struct {
	AuthType     string      `json:"auth_type"     binding:"required,oneof=oidc x509"`
	AuthMaterial interface{} `json:"auth_material" binding:"required"`
}

// GlobalCapabilitiesResponse is the response for the global capabilities endpoints.
// GlobalActions maps a qualified entity type (e.g. "public.device") to the list of granted
// global actions (e.g. ["create", "list"]).  Atomic actions are never included.
type GlobalCapabilitiesResponse struct {
	GlobalActions     map[string][]string `json:"global_actions"`
	MatchedPrincipals []string            `json:"matched_principals,omitempty"`
}

// --- Entity Capabilities ---

// EntityCapabilityQuery describes a single entity to evaluate in a batch request.
type EntityCapabilityQuery struct {
	Namespace  string        `json:"namespace"    binding:"required"`
	SchemaName string        `json:"schema_name"  binding:"required"`
	EntityType string        `json:"entity_type"  binding:"required"`
	EntityKey  FlexEntityKey `json:"entity_key"` // Primary key: string or {col: val} map
}

// GetEntityCapabilitiesRequest is the request body for POST /api/v1/authz/capabilities/entity.
// Queries accepts one or more entity queries evaluated in a single call.
type GetEntityCapabilitiesRequest struct {
	PrincipalID string                  `json:"principal_id" binding:"required"`
	Queries     []EntityCapabilityQuery `json:"queries"      binding:"required,min=1"`
}

// MatchAndGetEntityCapabilitiesRequest is the request body for
// POST /api/v1/authz/match/capabilities/entity.
type MatchAndGetEntityCapabilitiesRequest struct {
	AuthType     string                  `json:"auth_type"     binding:"required,oneof=oidc x509"`
	AuthMaterial interface{}             `json:"auth_material" binding:"required"`
	Queries      []EntityCapabilityQuery `json:"queries"       binding:"required,min=1"`
}

// EntityCapabilitiesResultDTO is a single entry in the batch response.
// If the query failed (e.g. unknown namespace), Error is non-empty and Actions is empty.
type EntityCapabilitiesResultDTO struct {
	Namespace  string            `json:"namespace"`
	SchemaName string            `json:"schema_name"`
	EntityType string            `json:"entity_type"`
	EntityKey  map[string]string `json:"entity_key"`
	Actions    []string          `json:"actions"`
	Error      string            `json:"error,omitempty"`
}

// EntityCapabilitiesResponse is the response for the entity capabilities endpoints.
// Results are returned in the same order as the input Queries.
type EntityCapabilitiesResponse struct {
	Results           []EntityCapabilitiesResultDTO `json:"results"`
	MatchedPrincipals []string                      `json:"matched_principals,omitempty"`
}
