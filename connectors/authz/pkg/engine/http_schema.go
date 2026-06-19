package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// HTTPMatchType describes how a route's path pattern is matched.
type HTTPMatchType string

const (
	HTTPMatchExact  HTTPMatchType = "exact"  // full equality: /api/v1/devices
	HTTPMatchPrefix HTTPMatchType = "prefix" // prefix: /api/v1/devices/** (strip trailing /**)
	HTTPMatchRegex  HTTPMatchType = "regex"  // full regexp anchored to the path
)

// HTTPRouteConfig maps a method+path pattern to a named logical action.
type HTTPRouteConfig struct {
	Name          string        `json:"name"`       // human-readable label
	Methods       []string      `json:"methods"`    // HTTP verbs; empty slice = wildcard (any method)
	Path          string        `json:"path"`       // pattern string
	MatchType     HTTPMatchType `json:"match_type"` // "exact" | "prefix" | "regex"
	Action        string        `json:"action"`     // logical action name, referenced in HTTPRule.Actions
	compiledRegex *regexp.Regexp
}

// HTTPSchemaDefinition describes an external REST API's routes and their action mappings.
// It is the HTTP-world analogue of SchemaDefinition: loaded from a JSON file, registered by name.
type HTTPSchemaDefinition struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Routes      []HTTPRouteConfig `json:"routes"`
	// AllActions is derived at load time from the unique Action values across all Routes.
	AllActions []string `json:"all_actions,omitempty"`
}

// MatchRoute returns the first HTTPRouteConfig whose method and path match the given inputs.
// Matching precedence: exact > prefix > regex; within each type, first-defined wins.
// Returns nil when no route matches.
func (s *HTTPSchemaDefinition) MatchRoute(method, path string) *HTTPRouteConfig {
	method = strings.ToUpper(method)
	for _, priority := range []HTTPMatchType{HTTPMatchExact, HTTPMatchPrefix, HTTPMatchRegex} {
		for i := range s.Routes {
			r := &s.Routes[i]
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
	if len(def.Routes) == 0 {
		return fmt.Errorf("at least one route is required")
	}
	actionSet := make(map[string]struct{})
	for i := range def.Routes {
		route := &def.Routes[i]
		if route.Action == "" {
			return fmt.Errorf("route at index %d: action is required", i)
		}
		if route.Path == "" {
			return fmt.Errorf("route at index %d: path is required", i)
		}
		switch route.MatchType {
		case HTTPMatchExact, HTTPMatchPrefix:
			// no extra validation needed
		case HTTPMatchRegex:
			re, err := regexp.Compile(route.Path)
			if err != nil {
				return fmt.Errorf("route at index %d: invalid regex %q: %w", i, route.Path, err)
			}
			route.compiledRegex = re
		default:
			return fmt.Errorf("route at index %d: unknown match_type %q (must be exact, prefix, or regex)", i, route.MatchType)
		}
		actionSet[route.Action] = struct{}{}
	}
	def.AllActions = make([]string, 0, len(actionSet))
	for a := range actionSet {
		def.AllActions = append(def.AllActions, a)
	}
	return nil
}
