package engine

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestHTTPRoutePathMatches covers the path-matching decision used by HTTP
// authorization. A bug here is a direct authz bypass (a request reaching a
// route it should not) or an over-block, so every match type and its boundary
// conditions are exercised.
func TestHTTPRoutePathMatches(t *testing.T) {
	regexRoute := &HTTPRouteConfig{
		MatchType:     HTTPMatchRegex,
		Path:          `^/api/v1/devices/[^/]+$`,
		compiledRegex: regexp.MustCompile(`^/api/v1/devices/[^/]+$`),
	}

	tests := []struct {
		name  string
		route *HTTPRouteConfig
		path  string
		want  bool
	}{
		// exact
		{"exact match", &HTTPRouteConfig{MatchType: HTTPMatchExact, Path: "/api/v1/devices"}, "/api/v1/devices", true},
		{"exact mismatch trailing slash", &HTTPRouteConfig{MatchType: HTTPMatchExact, Path: "/api/v1/devices"}, "/api/v1/devices/", false},
		{"exact mismatch subpath", &HTTPRouteConfig{MatchType: HTTPMatchExact, Path: "/api/v1/devices"}, "/api/v1/devices/1", false},

		// prefix — security critical: a sibling path sharing the prefix string
		// must NOT match (no /devices-secret bypass via /devices/** rule).
		{"prefix matches base exactly", &HTTPRouteConfig{MatchType: HTTPMatchPrefix, Path: "/api/v1/devices/**"}, "/api/v1/devices", true},
		{"prefix matches child", &HTTPRouteConfig{MatchType: HTTPMatchPrefix, Path: "/api/v1/devices/**"}, "/api/v1/devices/1", true},
		{"prefix matches deep child", &HTTPRouteConfig{MatchType: HTTPMatchPrefix, Path: "/api/v1/devices/**"}, "/api/v1/devices/1/jobs", true},
		{"prefix does NOT match sibling sharing prefix string", &HTTPRouteConfig{MatchType: HTTPMatchPrefix, Path: "/api/v1/devices/**"}, "/api/v1/devices-secret", false},
		{"prefix does NOT match shorter path", &HTTPRouteConfig{MatchType: HTTPMatchPrefix, Path: "/api/v1/devices/**"}, "/api/v1", false},

		// regex
		{"regex match", regexRoute, "/api/v1/devices/abc", true},
		{"regex mismatch extra segment", regexRoute, "/api/v1/devices/abc/jobs", false},
		{"regex nil compiled denies", &HTTPRouteConfig{MatchType: HTTPMatchRegex, Path: "x"}, "x", false},

		// unknown match type denies
		{"unknown match type denies", &HTTPRouteConfig{MatchType: HTTPMatchType("glob"), Path: "/x"}, "/x", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, httpRoutePathMatches(tc.route, tc.path))
		})
	}
}

// TestHTTPRouteMethodMatches covers HTTP-verb matching including the empty-list
// wildcard and the explicit "*" wildcard.
func TestHTTPRouteMethodMatches(t *testing.T) {
	tests := []struct {
		name   string
		route  *HTTPRouteConfig
		method string
		want   bool
	}{
		{"empty methods is wildcard", &HTTPRouteConfig{}, "GET", true},
		{"explicit match", &HTTPRouteConfig{Methods: []string{"GET", "POST"}}, "POST", true},
		{"case-insensitive match", &HTTPRouteConfig{Methods: []string{"get"}}, "GET", true},
		{"star wildcard", &HTTPRouteConfig{Methods: []string{"*"}}, "DELETE", true},
		{"no match", &HTTPRouteConfig{Methods: []string{"GET"}}, "POST", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, httpRouteMethodMatches(tc.route, tc.method))
		})
	}
}

// TestExtractHTTPConstraintRequestValue covers the request-value extraction used
// by route constraints. Each source's success and failure branches are exercised
// because a wrong extraction lets a constraint pass when it should fail.
func TestExtractHTTPConstraintRequestValue(t *testing.T) {
	regexRoute := &HTTPRouteConfig{
		MatchType:     HTTPMatchRegex,
		compiledRegex: regexp.MustCompile(`^/d/([^/]+)/j$`),
	}
	noRegexRoute := &HTTPRouteConfig{MatchType: HTTPMatchRegex}

	tests := []struct {
		name    string
		route   *HTTPRouteConfig
		req     HTTPCheckRequest
		ref     HTTPRequestValueRef
		wantVal string
		wantOK  bool
	}{
		// path_regex_group
		{"regex group extracts", regexRoute, HTTPCheckRequest{Path: "/d/dev-1/j"}, HTTPRequestValueRef{Source: "path_regex_group", Index: 1}, "dev-1", true},
		{"regex group nil compiled", noRegexRoute, HTTPCheckRequest{Path: "/d/dev-1/j"}, HTTPRequestValueRef{Source: "path_regex_group", Index: 1}, "", false},
		{"regex group index zero", regexRoute, HTTPCheckRequest{Path: "/d/dev-1/j"}, HTTPRequestValueRef{Source: "path_regex_group", Index: 0}, "", false},
		{"regex group index out of range", regexRoute, HTTPCheckRequest{Path: "/d/dev-1/j"}, HTTPRequestValueRef{Source: "path_regex_group", Index: 5}, "", false},
		{"regex group no match", regexRoute, HTTPCheckRequest{Path: "/nope"}, HTTPRequestValueRef{Source: "path_regex_group", Index: 1}, "", false},

		// query
		{"query present", &HTTPRouteConfig{}, HTTPCheckRequest{RawQuery: "device_id=dev-1"}, HTTPRequestValueRef{Source: "query", Name: "device_id"}, "dev-1", true},
		{"query absent", &HTTPRouteConfig{}, HTTPCheckRequest{RawQuery: "other=x"}, HTTPRequestValueRef{Source: "query", Name: "device_id"}, "", false},
		{"query empty value", &HTTPRouteConfig{}, HTTPCheckRequest{RawQuery: "device_id="}, HTTPRequestValueRef{Source: "query", Name: "device_id"}, "", false},
		{"query malformed", &HTTPRouteConfig{}, HTTPCheckRequest{RawQuery: "%zz"}, HTTPRequestValueRef{Source: "query", Name: "device_id"}, "", false},

		// header (exact key + case-insensitive fallback)
		{"header exact lowercase key", &HTTPRouteConfig{}, HTTPCheckRequest{Headers: map[string]string{"x-device-id": "dev-1"}}, HTTPRequestValueRef{Source: "header", Name: "x-device-id"}, "dev-1", true},
		{"header case-insensitive fallback", &HTTPRouteConfig{}, HTTPCheckRequest{Headers: map[string]string{"X-Device-Id": "dev-1"}}, HTTPRequestValueRef{Source: "header", Name: "X-Device-ID"}, "dev-1", true},
		{"header absent", &HTTPRouteConfig{}, HTTPCheckRequest{Headers: map[string]string{}}, HTTPRequestValueRef{Source: "header", Name: "x-device-id"}, "", false},

		// json_body
		{"json string value", &HTTPRouteConfig{}, HTTPCheckRequest{Body: []byte(`{"device":{"id":"dev-1"}}`)}, HTTPRequestValueRef{Source: "json_body", Path: "$.device.id"}, "dev-1", true},
		{"json numeric value", &HTTPRouteConfig{}, HTTPCheckRequest{Body: []byte(`{"count":42}`)}, HTTPRequestValueRef{Source: "json_body", Path: "$.count"}, "42", true},
		{"json bool value", &HTTPRouteConfig{}, HTTPCheckRequest{Body: []byte(`{"active":true}`)}, HTTPRequestValueRef{Source: "json_body", Path: "$.active"}, "true", true},
		{"json missing key", &HTTPRouteConfig{}, HTTPCheckRequest{Body: []byte(`{"device":{}}`)}, HTTPRequestValueRef{Source: "json_body", Path: "$.device.id"}, "", false},
		{"json non-object traversal", &HTTPRouteConfig{}, HTTPCheckRequest{Body: []byte(`{"device":"x"}`)}, HTTPRequestValueRef{Source: "json_body", Path: "$.device.id"}, "", false},
		{"json unsupported leaf type", &HTTPRouteConfig{}, HTTPCheckRequest{Body: []byte(`{"device":{"id":["x"]}}`)}, HTTPRequestValueRef{Source: "json_body", Path: "$.device.id"}, "", false},
		{"json empty string leaf", &HTTPRouteConfig{}, HTTPCheckRequest{Body: []byte(`{"id":""}`)}, HTTPRequestValueRef{Source: "json_body", Path: "$.id"}, "", false},
		{"json empty path part", &HTTPRouteConfig{}, HTTPCheckRequest{Body: []byte(`{"device":{"id":"x"}}`)}, HTTPRequestValueRef{Source: "json_body", Path: "$.device."}, "", false},
		{"json malformed body", &HTTPRouteConfig{}, HTTPCheckRequest{Body: []byte(`{`)}, HTTPRequestValueRef{Source: "json_body", Path: "$.id"}, "", false},
		{"json body too large", &HTTPRouteConfig{}, HTTPCheckRequest{BodyTooLarge: true, Body: []byte(`{"id":"x"}`)}, HTTPRequestValueRef{Source: "json_body", Path: "$.id"}, "", false},

		// unknown source
		{"unknown source", &HTTPRouteConfig{}, HTTPCheckRequest{}, HTTPRequestValueRef{Source: "cookie"}, "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			val, ok := extractHTTPConstraintRequestValue(tc.route, tc.req, tc.ref)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantVal, val)
		})
	}
}

// TestValidateHTTPRouteConstraint covers the load-time validation of route
// constraints — every rejection branch must fire so misconfigured policies are
// caught at load rather than silently passing authz checks.
func TestValidateHTTPRouteConstraint(t *testing.T) {
	regexRoute := &HTTPRouteConfig{MatchType: HTTPMatchRegex}
	exactRoute := &HTTPRouteConfig{MatchType: HTTPMatchExact}

	tests := []struct {
		name       string
		route      *HTTPRouteConfig
		constraint HTTPRouteConstraint
		wantErr    string
	}{
		{
			name:       "missing subject attribute",
			route:      regexRoute,
			constraint: HTTPRouteConstraint{Request: HTTPRequestValueRef{Source: "query", Name: "x"}},
			wantErr:    "equals_subject_attribute is required",
		},
		{
			name:       "path_regex_group on non-regex route",
			route:      exactRoute,
			constraint: HTTPRouteConstraint{Request: HTTPRequestValueRef{Source: "path_regex_group", Index: 1}, EqualsSubjectAttribute: "id"},
			wantErr:    "requires a regex route",
		},
		{
			name:       "path_regex_group non-positive index",
			route:      regexRoute,
			constraint: HTTPRouteConstraint{Request: HTTPRequestValueRef{Source: "path_regex_group", Index: 0}, EqualsSubjectAttribute: "id"},
			wantErr:    "index must be greater than zero",
		},
		{
			name:       "query missing name",
			route:      exactRoute,
			constraint: HTTPRouteConstraint{Request: HTTPRequestValueRef{Source: "query"}, EqualsSubjectAttribute: "id"},
			wantErr:    "name is required",
		},
		{
			name:       "header missing name",
			route:      exactRoute,
			constraint: HTTPRouteConstraint{Request: HTTPRequestValueRef{Source: "header"}, EqualsSubjectAttribute: "id"},
			wantErr:    "name is required",
		},
		{
			name:       "json_body missing path",
			route:      exactRoute,
			constraint: HTTPRouteConstraint{Request: HTTPRequestValueRef{Source: "json_body"}, EqualsSubjectAttribute: "id"},
			wantErr:    "json_body path is required",
		},
		{
			name:       "unsupported source",
			route:      exactRoute,
			constraint: HTTPRouteConstraint{Request: HTTPRequestValueRef{Source: "cookie"}, EqualsSubjectAttribute: "id"},
			wantErr:    "unsupported request source",
		},
		{
			name:       "valid regex group",
			route:      regexRoute,
			constraint: HTTPRouteConstraint{Request: HTTPRequestValueRef{Source: "path_regex_group", Index: 1}, EqualsSubjectAttribute: "id"},
		},
		{
			name:       "valid query",
			route:      exactRoute,
			constraint: HTTPRouteConstraint{Request: HTTPRequestValueRef{Source: "query", Name: "device_id"}, EqualsSubjectAttribute: "id"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.constraint
			err := validateHTTPRouteConstraint(tc.route, &c, "test")
			if tc.wantErr != "" {
				if assert.Error(t, err) {
					assert.Contains(t, err.Error(), tc.wantErr)
				}
				return
			}
			assert.NoError(t, err)
		})
	}
}
