package dto

// AuthorizeRequest for checking authorization
// Action can be either an atomicAction (requires entity key, e.g., "read", "write", "delete")
// or a globalAction (doesn't require entity key, e.g., "create", "list")
type AuthorizeRequest struct {
	PrincipalID string        `json:"principal_id" binding:"required"`
	Namespace   string        `json:"namespace" binding:"required"`
	SchemaName  string        `json:"schema_name" binding:"required"`
	Action      string        `json:"action" binding:"required"`      // Action name (atomicAction or globalAction)
	EntityType  string        `json:"entity_type" binding:"required"` // Unqualified entity type as defined in schema
	EntityKey   FlexEntityKey `json:"entity_key"`                     // Primary key: string or {col: val} map (required for atomicActions)
}

// MatchAndAuthorizeRequest for checking authorization with principal matching
type MatchAndAuthorizeRequest struct {
	AuthMaterial interface{}   `json:"auth_material" binding:"required"` // JWT or certificate data
	AuthType     string        `json:"auth_type" binding:"required"`     // "oidc" or "x509"
	Namespace    string        `json:"namespace" binding:"required"`
	SchemaName   string        `json:"schema_name" binding:"required"`
	Action       string        `json:"action" binding:"required"`
	EntityType   string        `json:"entity_type" binding:"required"`
	EntityKey    FlexEntityKey `json:"entity_key"`
}

// AuthorizeResponse returns authorization result
type AuthorizeResponse struct {
	Allowed    bool              `json:"allowed"`
	Namespace  string            `json:"namespace"`
	SchemaName string            `json:"schema_name"`
	EntityType string            `json:"entity_type"`
	EntityKey  map[string]string `json:"entity_key"`
	Action     string            `json:"action"`
}

// MatchAndAuthorizeResponse returns authorization result with matched principals
type MatchAndAuthorizeResponse struct {
	Allowed           bool              `json:"allowed"`
	Namespace         string            `json:"namespace"`
	SchemaName        string            `json:"schema_name"`
	EntityType        string            `json:"entity_type"`
	EntityKey         map[string]string `json:"entity_key"`
	Action            string            `json:"action"`
	MatchedPrincipals []string          `json:"matched_principals"`
}

// HTTPAuthzCheckRequestDetails contains the HTTP request to evaluate.
type HTTPAuthzCheckRequestDetails struct {
	Method   string            `json:"method" binding:"required"`
	Path     string            `json:"path" binding:"required"`
	RawQuery string            `json:"raw_query,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Body     string            `json:"body,omitempty"`
}

// HTTPAuthzCheckRequest checks an HTTP route for a known principal. SubjectAttributes
// are explicit test attributes; credential-derived mappings are only available through
// MatchHTTPAuthzCheckRequest.
type HTTPAuthzCheckRequest struct {
	PrincipalID       string                       `json:"principal_id" binding:"required"`
	SubjectAttributes map[string]string            `json:"subject_attributes,omitempty"`
	Request           HTTPAuthzCheckRequestDetails `json:"request" binding:"required"`
}

// MatchHTTPAuthzCheckRequest checks an HTTP route after resolving the supplied credential.
type MatchHTTPAuthzCheckRequest struct {
	AuthMaterial interface{}                  `json:"auth_material" binding:"required"`
	AuthType     string                       `json:"auth_type" binding:"required"`
	Request      HTTPAuthzCheckRequestDetails `json:"request" binding:"required"`
}

// HTTPAuthzCheckResponse contains a debug-friendly HTTP authorization decision.
type HTTPAuthzCheckResponse struct {
	Allowed            bool              `json:"allowed"`
	MatchedPrincipalID string            `json:"matched_principal_id,omitempty"`
	MatchedPrincipals  []string          `json:"matched_principals,omitempty"`
	MatchedPolicyID    string            `json:"matched_policy_id,omitempty"`
	MatchedAction      string            `json:"matched_action,omitempty"`
	SubjectAttributes  map[string]string `json:"subject_attributes,omitempty"`
	Reason             string            `json:"reason,omitempty"`
}

// GetFilterRequest for retrieving list filters
type GetFilterRequest struct {
	PrincipalID string `json:"principal_id" binding:"required"`
	Namespace   string `json:"namespace" binding:"required"`
	SchemaName  string `json:"schema_name" binding:"required"`
	EntityType  string `json:"entity_type" binding:"required"`
}

// MatchAndGetFilterRequest for retrieving list filters with principal matching
type MatchAndGetFilterRequest struct {
	AuthMaterial interface{} `json:"auth_material" binding:"required"` // JWT or certificate data
	AuthType     string      `json:"auth_type" binding:"required"`     // "oidc" or "x509"
	Namespace    string      `json:"namespace" binding:"required"`
	SchemaName   string      `json:"schema_name" binding:"required"`
	EntityType   string      `json:"entity_type" binding:"required"`
}

// GetFilterResponse returns SQL filter
type GetFilterResponse struct {
	Namespace   string `json:"namespace"`
	SchemaName  string `json:"schema_name"`
	EntityType  string `json:"entity_type"`
	FilterQuery string `json:"filter_query"`
}

// MatchAndGetFilterResponse returns SQL filter with matched principals
type MatchAndGetFilterResponse struct {
	Namespace         string   `json:"namespace"`
	SchemaName        string   `json:"schema_name"`
	EntityType        string   `json:"entity_type"`
	FilterQuery       string   `json:"filter_query"`
	MatchedPrincipals []string `json:"matched_principals"`
}

// ListPoliciesResponse returns available policies
type ListPoliciesResponse struct {
	Policies []PolicySummary `json:"policies"`
}

type PolicySummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	RuleCount   int    `json:"rule_count"`
}
