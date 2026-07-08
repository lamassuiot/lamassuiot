package engine

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/lamassuiot/authz/pkg/models"
)

// HTTPMatchType describes how a route's path pattern is matched.
type HTTPMatchType string

const (
	HTTPMatchExact  HTTPMatchType = "exact"  // full equality: /api/v1/devices
	HTTPMatchPrefix HTTPMatchType = "prefix" // prefix: /api/v1/devices/** (strip trailing /**)
	HTTPMatchRegex  HTTPMatchType = "regex"  // full regexp anchored to the path
)

// HTTPDefaultAction describes the fallback decision applied when a request
// path falls under a schema's base_paths but matches no configured route.
type HTTPDefaultAction string

const (
	HTTPDefaultActionAllow HTTPDefaultAction = "allow"
	HTTPDefaultActionDeny  HTTPDefaultAction = "deny"
)

// HTTPRouteConfig maps a method+path pattern to a named logical action.
type HTTPRouteConfig struct {
	Name        string                `json:"name"`                  // human-readable label
	Methods     []string              `json:"methods"`               // HTTP verbs; empty slice = wildcard (any method)
	Path        string                `json:"path"`                  // pattern string
	MatchType   HTTPMatchType         `json:"match_type"`            // "exact" | "prefix" | "regex"
	Action      string                `json:"action"`                // logical action name, referenced in HTTPRule.Actions
	Constraints []HTTPRouteConstraint `json:"constraints,omitempty"` // optional subject/request constraints
	// SkipAuthz allows the route once a subject has been authenticated, without
	// requiring any policy to grant its action. Authentication (identity
	// resolution) still runs; only the authorization decision is bypassed.
	SkipAuthz     bool `json:"skip_authz,omitempty"`
	compiledRegex *regexp.Regexp
}

// HTTPRouteConstraint requires a request-derived value to equal one normalized
// subject attribute for the same subject whose policy grants the route action.
type HTTPRouteConstraint struct {
	Request                HTTPRequestValueRef `json:"request"`
	EqualsSubjectAttribute string              `json:"equals_subject_attribute"`
}

// HTTPRequestValueRef identifies the request value used by a route constraint.
type HTTPRequestValueRef struct {
	Source string `json:"source"`          // path_regex_group | query | header | json_body
	Name   string `json:"name,omitempty"`  // query/header name
	Index  int    `json:"index,omitempty"` // regex capture group index
	Path   string `json:"path,omitempty"`  // JSON path, e.g. $.device_id
}

// HTTPCheckRequest is the request envelope for subject-aware HTTP authz.
type HTTPCheckRequest struct {
	Method       string
	Path         string
	RawQuery     string
	Headers      map[string]string
	Body         []byte
	BodyTooLarge bool
	Subjects     []SubjectPolicySet
}

// HTTPCheckResult contains the subject-aware HTTP authorization decision.
type HTTPCheckResult struct {
	Allowed            bool
	MatchedPolicyID    string
	MatchedPrincipalID string
	MatchedAction      string
}

// HTTPRouteGroupConfig groups related routes for presentation and introspection.
type HTTPRouteGroupConfig struct {
	Name        string            `json:"name"`                  // human-readable label
	Description string            `json:"description,omitempty"` // optional group description
	Routes      []HTTPRouteConfig `json:"routes"`                // routes covered by this group
	AllActions  []string          `json:"all_actions,omitempty"` // route actions derived at load time
}

// HTTPSchemaDefinition describes an external REST API's routes and their action mappings.
// It is the HTTP-world analogue of SchemaDefinition: loaded from a JSON file, registered by name.
type HTTPSchemaDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Routes      []HTTPRouteConfig      `json:"routes,omitempty"`
	Groups      []HTTPRouteGroupConfig `json:"groups,omitempty"`
	// BasePaths are the path prefixes owned by this schema (e.g. ["/api/wfx"]).
	// Used only to resolve DefaultAction for requests that fall under the
	// service's namespace but match no configured route.
	BasePaths []string `json:"base_paths,omitempty"`
	// DefaultAction is applied when a request path matches a BasePaths entry
	// but no route in this schema matches. "allow" or "deny"; empty behaves
	// like "deny" (the pre-existing implicit-deny behavior).
	DefaultAction HTTPDefaultAction `json:"default_action,omitempty"`
	// AllActions is derived at load time from the unique Action values across all Routes and Groups.
	AllActions     []string           `json:"all_actions,omitempty"`
	compiledRoutes []*HTTPRouteConfig `json:"-"`
}

// MatchRoute returns the first HTTPRouteConfig whose method and path match the given inputs.
// Matching precedence: exact > prefix > regex; within each type, first-defined wins.
// Returns nil when no route matches.
func (s *HTTPSchemaDefinition) MatchRoute(method, path string) *HTTPRouteConfig {
	return s.matchRouteEntry(method, path)
}

// MatchesBasePath reports whether path falls under one of the schema's BasePaths.
// prefixLen is the length of the matched base path, letting callers pick the
// most specific schema when multiple schemas' base paths overlap.
func (s *HTTPSchemaDefinition) MatchesBasePath(path string) (matched bool, prefixLen int) {
	best := -1
	for _, bp := range s.BasePaths {
		bp = strings.TrimSuffix(bp, "/")
		if path == bp || strings.HasPrefix(path, bp+"/") {
			if len(bp) > best {
				best = len(bp)
			}
		}
	}
	return best >= 0, best
}

func (s *HTTPSchemaDefinition) matchRouteEntry(method, path string) *HTTPRouteConfig {
	method = strings.ToUpper(method)
	for _, priority := range []HTTPMatchType{HTTPMatchExact, HTTPMatchPrefix, HTTPMatchRegex} {
		for _, r := range s.compiledRoutes {
			if r.MatchType != priority {
				continue
			}
			if !httpRouteMethodMatches(r, method) {
				continue
			}
			if httpRoutePathMatches(r, path) {
				return r
			}
		}
	}
	return nil
}

func httpRouteMethodMatches(r *HTTPRouteConfig, method string) bool {
	if len(r.Methods) == 0 {
		return true // wildcard
	}
	for _, m := range r.Methods {
		if strings.ToUpper(m) == method || m == "*" {
			return true
		}
	}
	return false
}

func httpRoutePathMatches(r *HTTPRouteConfig, path string) bool {
	switch r.MatchType {
	case HTTPMatchExact:
		return r.Path == path
	case HTTPMatchPrefix:
		prefix := strings.TrimSuffix(r.Path, "/**")
		return path == prefix || strings.HasPrefix(path, prefix+"/")
	case HTTPMatchRegex:
		if r.compiledRegex == nil {
			return false
		}
		return r.compiledRegex.MatchString(path)
	}
	return false
}

// HTTPSchemaRegistry holds all loaded HTTPSchemaDefinitions keyed by schema name.
type HTTPSchemaRegistry struct {
	schemas map[string]*HTTPSchemaDefinition
}

// NewHTTPSchemaRegistry creates an empty registry.
func NewHTTPSchemaRegistry() *HTTPSchemaRegistry {
	return &HTTPSchemaRegistry{schemas: make(map[string]*HTTPSchemaDefinition)}
}

// Load reads and parses an HTTP schema JSON file. The file must contain a JSON array
// of HTTPSchemaDefinition objects. Each schema name must be unique across all loaded files.
func (r *HTTPSchemaRegistry) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read http schema file %s: %w", path, err)
	}
	var defs []HTTPSchemaDefinition
	if err := json.Unmarshal(data, &defs); err != nil {
		return fmt.Errorf("parse http schema JSON from %s: %w", path, err)
	}
	for i := range defs {
		def := &defs[i]
		if err := r.validateAndCompile(def); err != nil {
			return fmt.Errorf("invalid http schema %q in %s: %w", def.Name, path, err)
		}
		if _, exists := r.schemas[def.Name]; exists {
			return fmt.Errorf("duplicate http schema name %q (from %s)", def.Name, path)
		}
		r.schemas[def.Name] = def
	}
	return nil
}

// Get retrieves an HTTP schema by name. Returns an error when not found.
func (r *HTTPSchemaRegistry) Get(name string) (*HTTPSchemaDefinition, error) {
	s, ok := r.schemas[name]
	if !ok {
		return nil, fmt.Errorf("http schema %q not found", name)
	}
	return s, nil
}

// GetAll returns all registered schemas. The returned map must not be mutated.
func (r *HTTPSchemaRegistry) GetAll() map[string]*HTTPSchemaDefinition {
	return r.schemas
}

func (r *HTTPSchemaRegistry) validateAndCompile(def *HTTPSchemaDefinition) error {
	if def.Name == "" {
		return fmt.Errorf("name is required")
	}
	if len(def.Routes) == 0 && len(def.Groups) == 0 {
		return fmt.Errorf("at least one route or group is required")
	}

	switch def.DefaultAction {
	case "", HTTPDefaultActionAllow, HTTPDefaultActionDeny:
	default:
		return fmt.Errorf("default_action must be %q or %q, got %q", HTTPDefaultActionAllow, HTTPDefaultActionDeny, def.DefaultAction)
	}
	if def.DefaultAction != "" && len(def.BasePaths) == 0 {
		return fmt.Errorf("default_action requires at least one base_path")
	}
	for i, bp := range def.BasePaths {
		if bp == "" || !strings.HasPrefix(bp, "/") {
			return fmt.Errorf("base_paths[%d]: must be a non-empty absolute path", i)
		}
	}

	def.compiledRoutes = nil
	actionSet := make(map[string]struct{})
	for i := range def.Routes {
		route := &def.Routes[i]
		if route.Action == "" {
			return fmt.Errorf("route at index %d: action is required", i)
		}
		if err := validateAndCompileHTTPRoute(route, fmt.Sprintf("route at index %d", i)); err != nil {
			return err
		}
		actionSet[route.Action] = struct{}{}
		def.compiledRoutes = append(def.compiledRoutes, route)
	}
	for i := range def.Groups {
		group := &def.Groups[i]
		if group.Name == "" {
			return fmt.Errorf("group at index %d: name is required", i)
		}
		if len(group.Routes) == 0 {
			return fmt.Errorf("group %q: at least one route is required", group.Name)
		}
		groupActionSet := make(map[string]struct{})
		for j := range group.Routes {
			route := &group.Routes[j]
			if route.Action == "" {
				return fmt.Errorf("group %q route at index %d: action is required", group.Name, j)
			}
			if err := validateAndCompileHTTPRoute(route, fmt.Sprintf("group %q route at index %d", group.Name, j)); err != nil {
				return err
			}
			actionSet[route.Action] = struct{}{}
			groupActionSet[route.Action] = struct{}{}
			def.compiledRoutes = append(def.compiledRoutes, route)
		}
		group.AllActions = sortedKeys(groupActionSet)
	}
	def.AllActions = sortedKeys(actionSet)
	return nil
}

func validateAndCompileHTTPRoute(route *HTTPRouteConfig, label string) error {
	if route.Path == "" {
		return fmt.Errorf("%s: path is required", label)
	}
	switch route.MatchType {
	case HTTPMatchExact, HTTPMatchPrefix:
		// no extra validation needed
	case HTTPMatchRegex:
		re, err := regexp.Compile(route.Path)
		if err != nil {
			return fmt.Errorf("%s: invalid regex %q: %w", label, route.Path, err)
		}
		route.compiledRegex = re
	default:
		return fmt.Errorf("%s: unknown match_type %q (must be exact, prefix, or regex)", label, route.MatchType)
	}

	if route.SkipAuthz && len(route.Constraints) > 0 {
		return fmt.Errorf("%s: skip_authz routes cannot declare constraints", label)
	}

	for i := range route.Constraints {
		if err := validateHTTPRouteConstraint(route, &route.Constraints[i], fmt.Sprintf("%s constraint at index %d", label, i)); err != nil {
			return err
		}
	}
	return nil
}

func validateHTTPRouteConstraint(route *HTTPRouteConfig, constraint *HTTPRouteConstraint, label string) error {
	if constraint.EqualsSubjectAttribute == "" {
		return fmt.Errorf("%s: equals_subject_attribute is required", label)
	}
	switch constraint.Request.Source {
	case "path_regex_group":
		if route.MatchType != HTTPMatchRegex {
			return fmt.Errorf("%s: path_regex_group requires a regex route", label)
		}
		if constraint.Request.Index <= 0 {
			return fmt.Errorf("%s: path_regex_group index must be greater than zero", label)
		}
	case "query", "header":
		if constraint.Request.Name == "" {
			return fmt.Errorf("%s: %s name is required", label, constraint.Request.Source)
		}
	case "json_body":
		if constraint.Request.Path == "" {
			return fmt.Errorf("%s: json_body path is required", label)
		}
	default:
		return fmt.Errorf("%s: unsupported request source %q", label, constraint.Request.Source)
	}
	return nil
}

func httpRouteConstraintsMatch(route *HTTPRouteConfig, req HTTPCheckRequest, subject ResolvedSubject) bool {
	for i := range route.Constraints {
		constraint := &route.Constraints[i]
		requestValue, ok := extractHTTPConstraintRequestValue(route, req, constraint.Request)
		if !ok {
			return false
		}
		subjectValue, ok := subject.Attributes[constraint.EqualsSubjectAttribute]
		if !ok {
			return false
		}
		if requestValue != subjectValue {
			return false
		}
	}
	return true
}

// httpRuleParamConstraintsMatch enforces a policy grant's param_constraints:
// literal values, written into the policy itself rather than derived from the
// subject, that a named regex capture group in the route's path must equal.
// A grant with no param_constraints for this action is unrestricted (backward
// compatible). Multiple constraints for the same action are ANDed.
func httpRuleParamConstraintsMatch(route *HTTPRouteConfig, rule *models.HTTPRule, req HTTPCheckRequest) bool {
	var applicable []*models.HTTPRuleParamConstraint
	for i := range rule.ParamConstraints {
		if rule.ParamConstraints[i].Action == route.Action {
			applicable = append(applicable, rule.ParamConstraints[i])
		}
	}
	if len(applicable) == 0 {
		return true
	}

	params := extractNamedPathParams(route, req.Path)
	for _, constraint := range applicable {
		for name, want := range constraint.Params {
			got, ok := params[name]
			if !ok || got != want {
				return false
			}
		}
	}
	return true
}

// extractNamedPathParams returns the route regex's named capture groups for
// path, keyed by group name. Returns nil when the route has no compiled regex
// or the path does not match.
func extractNamedPathParams(route *HTTPRouteConfig, path string) map[string]string {
	if route.compiledRegex == nil {
		return nil
	}
	matches := route.compiledRegex.FindStringSubmatch(path)
	if matches == nil {
		return nil
	}
	names := route.compiledRegex.SubexpNames()
	params := make(map[string]string, len(names))
	for i, name := range names {
		if i == 0 || name == "" {
			continue
		}
		params[name] = matches[i]
	}
	return params
}

func extractHTTPConstraintRequestValue(route *HTTPRouteConfig, req HTTPCheckRequest, ref HTTPRequestValueRef) (string, bool) {
	switch ref.Source {
	case "path_regex_group":
		if route.compiledRegex == nil {
			return "", false
		}
		matches := route.compiledRegex.FindStringSubmatch(req.Path)
		if ref.Index <= 0 || ref.Index >= len(matches) {
			return "", false
		}
		return matches[ref.Index], true
	case "query":
		values, err := url.ParseQuery(req.RawQuery)
		if err != nil {
			return "", false
		}
		value := values.Get(ref.Name)
		return value, value != ""
	case "header":
		value := req.Headers[strings.ToLower(ref.Name)]
		if value == "" {
			for key, candidate := range req.Headers {
				if strings.EqualFold(key, ref.Name) {
					value = candidate
					break
				}
			}
		}
		return value, value != ""
	case "json_body":
		return extractJSONBodyValue(req, ref.Path)
	default:
		return "", false
	}
}

func extractJSONBodyValue(req HTTPCheckRequest, path string) (string, bool) {
	if req.BodyTooLarge || len(req.Body) == 0 {
		return "", false
	}

	var body interface{}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return "", false
	}

	parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(path, "$."), "."), ".")
	current := body
	for _, part := range parts {
		if part == "" {
			return "", false
		}
		object, ok := current.(map[string]interface{})
		if !ok {
			return "", false
		}
		current, ok = object[part]
		if !ok {
			return "", false
		}
	}

	switch value := current.(type) {
	case string:
		return value, value != ""
	case float64, bool:
		return fmt.Sprintf("%v", value), true
	default:
		return "", false
	}
}

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
