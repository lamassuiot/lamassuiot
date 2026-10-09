package dto

// ExtAuthzCheckRequest mirrors the JSON encoding of Envoy's
// envoy.service.auth.v3.CheckRequest. Only the fields used by this service
// are modelled; extras are silently ignored during JSON unmarshalling.
type ExtAuthzCheckRequest struct {
	Attributes *CheckRequestAttributes `json:"attributes"`
}

// CheckRequestAttributes holds source/destination/request context from Envoy.
type CheckRequestAttributes struct {
	Request *AttributesRequest `json:"request"`
}

// AttributesRequest wraps the HTTP request context.
type AttributesRequest struct {
	HTTP *ExtAuthzHTTPRequest `json:"http"`
}

// ExtAuthzHTTPRequest contains the inbound HTTP request metadata sent by Envoy.
type ExtAuthzHTTPRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Host    string            `json:"host,omitempty"`
	Scheme  string            `json:"scheme,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// ExtAuthzCheckResponse is returned by the ext_authz endpoint.
// The HTTP status code carries the authoritative decision (200 = allowed, 403 = denied);
// the JSON body is informational and may be logged by Envoy.
type ExtAuthzCheckResponse struct {
	Allowed           bool     `json:"allowed"`
	MatchedPolicyID   string   `json:"matched_policy_id,omitempty"`
	MatchedPrincipals []string `json:"matched_principals,omitempty"`
	Reason            string   `json:"reason,omitempty"`
}
