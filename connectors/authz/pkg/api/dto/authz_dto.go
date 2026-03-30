package dto

// AuthorizeRequest for checking authorization
// Action can be either an atomicAction (requires entity key, e.g., "read", "write", "delete")
// or a globalAction (doesn't require entity key, e.g., "create", "list")
type AuthorizeRequest struct {
	PrincipalID string        `json:"principalId" binding:"required"`
	Namespace   string        `json:"namespace" binding:"required"`
	SchemaName  string        `json:"schemaName" binding:"required"`
	Action      string        `json:"action" binding:"required"`     // Action name (atomicAction or globalAction)
	EntityType  string        `json:"entityType" binding:"required"` // Unqualified entity type as defined in schema
	EntityKey   FlexEntityKey `json:"entityKey"`                     // Primary key: string or {col: val} map (required for atomicActions)
}

// MatchAndAuthorizeRequest for checking authorization with principal matching
type MatchAndAuthorizeRequest struct {
	AuthMaterial interface{}   `json:"authMaterial" binding:"required"` // JWT or certificate data
	AuthType     string        `json:"authType" binding:"required"`     // "oidc" or "x509"
	Namespace    string        `json:"namespace" binding:"required"`
	SchemaName   string        `json:"schemaName" binding:"required"`
	Action       string        `json:"action" binding:"required"`
	EntityType   string        `json:"entityType" binding:"required"`
	EntityKey    FlexEntityKey `json:"entityKey"`
}

// AuthorizeResponse returns authorization result
type AuthorizeResponse struct {
	Allowed    bool              `json:"allowed"`
	Namespace  string            `json:"namespace"`
	SchemaName string            `json:"schemaName"`
	EntityType string            `json:"entityType"`
	EntityKey  map[string]string `json:"entityKey"`
	Action     string            `json:"action"`
}

// MatchAndAuthorizeResponse returns authorization result with matched principals
type MatchAndAuthorizeResponse struct {
	Allowed           bool              `json:"allowed"`
	Namespace         string            `json:"namespace"`
	SchemaName        string            `json:"schemaName"`
	EntityType        string            `json:"entityType"`
	EntityKey         map[string]string `json:"entityKey"`
	Action            string            `json:"action"`
	MatchedPrincipals []string          `json:"matchedPrincipals"`
}

// GetFilterRequest for retrieving list filters
type GetFilterRequest struct {
	PrincipalID string `json:"principalId" binding:"required"`
	Namespace   string `json:"namespace" binding:"required"`
	SchemaName  string `json:"schemaName" binding:"required"`
	EntityType  string `json:"entityType" binding:"required"`
}

// MatchAndGetFilterRequest for retrieving list filters with principal matching
type MatchAndGetFilterRequest struct {
	AuthMaterial interface{} `json:"authMaterial" binding:"required"` // JWT or certificate data
	AuthType     string      `json:"authType" binding:"required"`     // "oidc" or "x509"
	Namespace    string      `json:"namespace" binding:"required"`
	SchemaName   string      `json:"schemaName" binding:"required"`
	EntityType   string      `json:"entityType" binding:"required"`
}

// GetFilterResponse returns SQL filter
type GetFilterResponse struct {
	Namespace   string `json:"namespace"`
	SchemaName  string `json:"schemaName"`
	EntityType  string `json:"entityType"`
	FilterQuery string `json:"filterQuery"`
}

// MatchAndGetFilterResponse returns SQL filter with matched principals
type MatchAndGetFilterResponse struct {
	Namespace         string   `json:"namespace"`
	SchemaName        string   `json:"schemaName"`
	EntityType        string   `json:"entityType"`
	FilterQuery       string   `json:"filterQuery"`
	MatchedPrincipals []string `json:"matchedPrincipals"`
}

// ListPoliciesResponse returns available policies
type ListPoliciesResponse struct {
	Policies []PolicySummary `json:"policies"`
}

type PolicySummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	RuleCount   int    `json:"ruleCount"`
}
