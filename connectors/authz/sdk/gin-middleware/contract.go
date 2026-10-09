package middleware

import (
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/core"
	authzengine "github.com/lamassuiot/authz/pkg/engine"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// Declaration is shared by the recorded route contract and OpenAPI x-authz.
type Declaration struct {
	Namespace  string `yaml:"namespace" json:"namespace"`
	SchemaName string `yaml:"schema_name" json:"schema_name"`
	EntityType string `yaml:"entity_type" json:"entity_type"`
	Action     string `yaml:"action" json:"action"`
	Check      string `yaml:"check,omitempty" json:"check,omitempty"`
}

// Declaration.Check values for permissions that are not a single domain action.
const (
	checkFilter     = "filter"
	checkPublic     = "public"
	checkEST        = "est"
	checkEnvoy      = "envoy"
	checkEvaluation = "evaluation"
)

// handlerChecks are the protocol checks performed by the endpoint itself. The value
// says whether the route must also record a trust boundary: Envoy and evaluation
// callers are anonymous at the HTTP layer, EST clients authenticate with certificates.
var handlerChecks = map[string]bool{
	checkEST:        false,
	checkEnvoy:      true,
	checkEvaluation: true,
}

// Permission couples validated metadata with the middleware that enforces it.
// Its fields are private so callers cannot attach different metadata and middleware.
type Permission struct {
	declaration   Declaration
	handler       gin.HandlerFunc
	pathParams    []string
	trustBoundary string
}

// WithTrustBoundary records an intended caller boundary. Today it is equivalent
// to public access: it adds no caller authentication or network restriction.
// Enforcement may be introduced here in the future.
func (p Permission) WithTrustBoundary(name string) Permission {
	if name != "internal-gateway" && name != "internal-service" {
		panic("unknown trust boundary: " + name)
	}
	if p.declaration.Check != checkPublic && !handlerChecks[p.declaration.Check] {
		panic("trust boundary currently requires public caller access")
	}
	p.trustBoundary = name
	return p
}

// Public records an intentionally anonymous endpoint without calling authz.
func Public() Permission {
	return Permission{declaration: Declaration{Check: checkPublic}, handler: func(c *gin.Context) { c.Next() }}
}

// DelegatedAuthorization records that authorization is delegated to the endpoint/service itself
// (protocol checks).
// It deliberately adds no domain guard: EST, Envoy and evaluation APIs handle their own credentials.
func DelegatedAuthorization(kind string) Permission {
	if _, known := handlerChecks[kind]; !known {
		panic("unknown delegated authorization kind:" + kind)
	}
	return Permission{declaration: Declaration{Check: kind}, handler: func(c *gin.Context) { c.Next() }}
}

// MustNewAuthzMiddleware validates the entity while the application builds its router.
// Existing unvalidated constructors remain available for other services.
func MustNewAuthzMiddleware(authzEngine core.AuthzEngine, registry *authzengine.SchemaRegistry, namespace, schemaName, entityType string, logger *logrus.Entry) *AuthzMiddleware {
	if registry == nil || authzEngine == nil {
		panic("authz middleware requires a schema registry and engine")
	}
	definition, err := registry.GetBySchemaEntity(schemaName, entityType)
	if err != nil {
		panic(fmt.Sprintf("invalid authz declaration: %s.%s.%s: %v", namespace, schemaName, entityType, err))
	}
	if definition.ConfigSchema != namespace {
		panic(fmt.Sprintf("invalid authz namespace %q for %s.%s; expected %q", namespace, schemaName, entityType, definition.ConfigSchema))
	}
	return &AuthzMiddleware{engine: authzEngine, namespace: namespace, schemaName: schemaName, entityType: entityType, entityPrimaryKeys: append([]string{}, definition.PrimaryKeys...), definition: definition, logger: logger}
}

// Global validates the action at registration time, before any request is served.
func (m *AuthzMiddleware) Global(action string) Permission {
	if m.definition == nil {
		panic("Global requires a schema-validated authz middleware")
	}
	handler := m.AuthzCheckCustom(action, func(*gin.Context) map[string]string { return nil })
	if !m.definition.IsGlobalAction(action) {
		panic(fmt.Sprintf("invalid authz declaration: %s.%s.%s action %q is not global", m.namespace, m.schemaName, m.entityType, action))
	}
	return Permission{declaration: Declaration{Namespace: m.namespace, SchemaName: m.schemaName, EntityType: m.entityType, Action: action}, handler: handler}
}

// Resource maps every schema primary key to a named Gin path parameter.
func (m *AuthzMiddleware) Resource(action string, keyParams map[string]string) Permission {
	if m.definition == nil || !m.definition.IsAtomicAction(action) {
		panic(fmt.Sprintf("invalid authz resource action %q for %s.%s.%s", action, m.namespace, m.schemaName, m.entityType))
	}
	if len(keyParams) != len(m.definition.PrimaryKeys) {
		panic("authz resource requires every schema primary key")
	}
	// Copy bindings so caller mutations cannot change the enforced resource key.
	bindings := make(map[string]string, len(keyParams))
	boundTo := make(map[string]string, len(keyParams))
	for _, key := range m.definition.PrimaryKeys {
		param := keyParams[key]
		if param == "" || strings.ContainsAny(param, "/:*") {
			panic(fmt.Sprintf("invalid authz path parameter for primary key %q", key))
		}
		if other, dup := boundTo[param]; dup {
			panic(fmt.Sprintf("authz path parameter %q is bound to both primary keys %q and %q", param, other, key))
		}
		boundTo[param] = key
		bindings[key] = param
	}
	handler := m.AuthzCheckCustom(action, func(c *gin.Context) map[string]string {
		key := make(map[string]string, len(bindings))
		for column, param := range bindings {
			key[column] = c.Param(param)
		}
		return key
	})
	params := make([]string, 0, len(bindings))
	for _, column := range m.definition.PrimaryKeys {
		params = append(params, bindings[column])
	}
	return Permission{declaration: Declaration{Namespace: m.namespace, SchemaName: m.schemaName, EntityType: m.entityType, Action: action}, handler: handler, pathParams: params}
}

// ResourceCustom resolves a path identifier into a composite key, such as a KMS URI or alias.
func (m *AuthzMiddleware) ResourceCustom(action, pathParam string, extractor func(*gin.Context) map[string]string) Permission {
	if m.definition == nil || !m.definition.IsAtomicAction(action) {
		panic(fmt.Sprintf("invalid authz resource action %q for %s.%s.%s", action, m.namespace, m.schemaName, m.entityType))
	}
	if extractor == nil || pathParam == "" || strings.ContainsAny(pathParam, "/:*") {
		panic("authz custom resource requires a path parameter and extractor")
	}
	handler := m.AuthzCheckCustom(action, func(c *gin.Context) map[string]string {
		key := extractor(c)
		if c.IsAborted() {
			return nil
		}
		// Never authorize a partial key or keys outside the domain definition.
		complete := len(key) == len(m.definition.PrimaryKeys)
		for _, column := range m.definition.PrimaryKeys {
			complete = complete && key[column] != ""
		}
		if !complete {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid authorization resource key"})
			return nil
		}
		return key
	})
	return Permission{declaration: Declaration{Namespace: m.namespace, SchemaName: m.schemaName, EntityType: m.entityType, Action: action}, handler: handler, pathParams: []string{pathParam}}
}

// List records the existing filter check, which computes readable resources.
func (m *AuthzMiddleware) List() Permission {
	if m.definition == nil || !m.definition.IsAtomicAction("read") {
		panic("authz list filter requires a schema with an atomic read action")
	}
	return Permission{declaration: Declaration{Namespace: m.namespace, SchemaName: m.schemaName, EntityType: m.entityType, Check: checkFilter}, handler: m.AuthListCheck()}
}

type RouteDeclaration struct {
	Method, Path  string
	Authz         Declaration
	TrustBoundary string
}

// ContractRouter registers and records a permission together. ValidateRoutes
// detects ordinary Gin registrations that bypass this contract within its group.
type ContractRouter struct {
	group *gin.RouterGroup
	// Shared with sub-routers so the root sees every route of the contract.
	routes *[]RouteDeclaration
}

func NewContractRouter(group *gin.RouterGroup) *ContractRouter {
	return &ContractRouter{group: group, routes: &[]RouteDeclaration{}}
}

// Group mirrors gin.RouterGroup.Group; its routes are recorded in the same contract.
func (r *ContractRouter) Group(relativePath string) *ContractRouter {
	return &ContractRouter{group: r.group.Group(relativePath), routes: r.routes}
}

func (r *ContractRouter) GET(relativePath string, permission Permission, handlers ...gin.HandlerFunc) {
	r.Handle(http.MethodGet, relativePath, permission, handlers...)
}

func (r *ContractRouter) POST(relativePath string, permission Permission, handlers ...gin.HandlerFunc) {
	r.Handle(http.MethodPost, relativePath, permission, handlers...)
}

func (r *ContractRouter) PUT(relativePath string, permission Permission, handlers ...gin.HandlerFunc) {
	r.Handle(http.MethodPut, relativePath, permission, handlers...)
}

func (r *ContractRouter) PATCH(relativePath string, permission Permission, handlers ...gin.HandlerFunc) {
	r.Handle(http.MethodPatch, relativePath, permission, handlers...)
}

func (r *ContractRouter) DELETE(relativePath string, permission Permission, handlers ...gin.HandlerFunc) {
	r.Handle(http.MethodDelete, relativePath, permission, handlers...)
}

func (r *ContractRouter) Handle(method, relativePath string, permission Permission, handlers ...gin.HandlerFunc) {
	if permission.handler == nil || len(handlers) == 0 {
		panic("contract route requires a validated permission and endpoint handler")
	}
	if handlerChecks[permission.declaration.Check] && permission.trustBoundary == "" {
		panic("delegated authorization requires an explicit trust boundary")
	}
	fullPath := joinPaths(r.group.BasePath(), relativePath)
	params := map[string]bool{}
	for _, segment := range strings.Split(fullPath, "/") {
		// Named (:id) and catch-all (*path) segments are both Gin path parameters.
		if strings.HasPrefix(segment, ":") || strings.HasPrefix(segment, "*") {
			params[segment[1:]] = true
		}
	}
	for _, param := range permission.pathParams {
		if !params[param] {
			panic(fmt.Sprintf("authz resource parameter %q missing from route %s %s", param, method, relativePath))
		}
	}
	r.group.Handle(method, relativePath, append([]gin.HandlerFunc{permission.handler}, handlers...)...)
	*r.routes = append(*r.routes, RouteDeclaration{Method: method, Path: fullPath, Authz: permission.declaration, TrustBoundary: permission.trustBoundary})
}

// joinPaths mirrors Gin's own joinPaths so the recorded path is the registered one:
// an empty relative path keeps the base unchanged, including a trailing slash.
func joinPaths(absolutePath, relativePath string) string {
	if relativePath == "" {
		return absolutePath
	}
	finalPath := path.Join(absolutePath, relativePath)
	if strings.HasSuffix(relativePath, "/") && !strings.HasSuffix(finalPath, "/") {
		return finalPath + "/"
	}
	return finalPath
}

func (r *ContractRouter) Declarations() []RouteDeclaration {
	return append([]RouteDeclaration{}, *r.routes...)
}

// ValidateRoutes checks every actual Gin route in this group against the contract.
func (r *ContractRouter) ValidateRoutes(actual gin.RoutesInfo) error {
	base := strings.TrimRight(r.group.BasePath(), "/")
	inGroup := func(routePath string) bool {
		return routePath == base || strings.HasPrefix(routePath, base+"/")
	}
	declared := map[string]bool{}
	for _, route := range *r.routes {
		if inGroup(route.Path) {
			declared[route.Method+" "+route.Path] = true
		}
	}
	for _, route := range actual {
		if !inGroup(route.Path) {
			continue
		}
		key := route.Method + " " + route.Path
		if !declared[key] {
			return fmt.Errorf("authz contract missing for registered route %s", key)
		}
		delete(declared, key)
	}
	if len(declared) > 0 {
		keys := make([]string, 0, len(declared))
		for key := range declared {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return fmt.Errorf("registered route missing for authz contract %s", keys[0])
	}
	return nil
}

// ValidateOpenAPI requires a one-to-one match between contracts and all operations.
// The PoC supports a static root-relative server prefix, as used by the service specs.
func (r *ContractRouter) ValidateOpenAPI(input io.Reader) error {
	var doc struct {
		Version string `yaml:"openapi"`
		Servers []struct {
			URL string `yaml:"url"`
		} `yaml:"servers"`
		Paths      map[string]map[string]yaml.Node `yaml:"paths"`
		Security   []map[string][]string           `yaml:"security"`
		Components struct {
			SecuritySchemes map[string]yaml.Node `yaml:"securitySchemes"`
		} `yaml:"components"`
	}
	decoder := yaml.NewDecoder(input)
	if err := decoder.Decode(&doc); err != nil {
		return fmt.Errorf("invalid OpenAPI: %w", err)
	}
	if !strings.HasPrefix(doc.Version, "3.") {
		return fmt.Errorf("expected an OpenAPI 3 document")
	}
	// A requirement naming an undefined scheme documents no usable authentication.
	undefinedScheme := func(security []map[string][]string) string {
		for _, requirement := range security {
			for name := range requirement {
				if _, defined := doc.Components.SecuritySchemes[name]; !defined {
					return name
				}
			}
		}
		return ""
	}
	if name := undefinedScheme(doc.Security); name != "" {
		return fmt.Errorf("OpenAPI security scheme %q is not defined in components.securitySchemes", name)
	}
	prefix := ""
	if len(doc.Servers) > 0 {
		prefix = strings.TrimRight(doc.Servers[0].URL, "/")
	}
	if (prefix != "" && !strings.HasPrefix(prefix, "/")) || strings.ContainsAny(prefix, "{}?#") {
		return fmt.Errorf("contract PoC requires a static root-relative OpenAPI server")
	}
	covered := map[string]bool{}
	for _, route := range *r.routes {
		if prefix != "" && !strings.HasPrefix(route.Path, prefix+"/") && route.Path != prefix {
			return fmt.Errorf("route %s %s does not match OpenAPI server %s", route.Method, route.Path, prefix)
		}
		relativePath := strings.TrimPrefix(route.Path, prefix)
		// A route at the server URL itself is the OpenAPI root path.
		if relativePath == "" {
			relativePath = "/"
		}
		segments := strings.Split(relativePath, "/")
		for i, segment := range segments {
			if strings.HasPrefix(segment, ":") || strings.HasPrefix(segment, "*") {
				segments[i] = "{" + segment[1:] + "}"
			}
		}
		relativePath = strings.Join(segments, "/")
		covered[strings.ToLower(route.Method)+" "+relativePath] = true
		methodKey := strings.ToLower(route.Method)
		node, exists := doc.Paths[relativePath][methodKey]
		if !exists {
			return fmt.Errorf("OpenAPI operation missing for %s %s", route.Method, route.Path)
		}
		var op struct {
			Authz         *Declaration           `yaml:"x-authz"`
			Security      *[]map[string][]string `yaml:"security"`
			TrustBoundary string                 `yaml:"x-trust-boundary"`
		}
		if err := node.Decode(&op); err != nil {
			return fmt.Errorf("invalid OpenAPI operation %s %s: %w", route.Method, route.Path, err)
		}
		if op.Security != nil {
			if name := undefinedScheme(*op.Security); name != "" {
				return fmt.Errorf("OpenAPI security scheme %q for %s %s is not defined in components.securitySchemes", name, route.Method, route.Path)
			}
		}
		if op.Authz == nil {
			return fmt.Errorf("OpenAPI x-authz missing for %s %s", route.Method, route.Path)
		}
		if *op.Authz != route.Authz {
			return fmt.Errorf("authz contract mismatch for %s %s: middleware=%+v; OpenAPI=%+v", route.Method, route.Path, route.Authz, *op.Authz)
		}
		if op.TrustBoundary != route.TrustBoundary {
			return fmt.Errorf("trust boundary mismatch for %s %s: middleware=%q; OpenAPI=%q", route.Method, route.Path, route.TrustBoundary, op.TrustBoundary)
		}
		if route.TrustBoundary != "" {
			if op.Security == nil || len(*op.Security) != 0 {
				return fmt.Errorf("trust boundary operation %s %s must explicitly declare security: [] while enforcement is not configured", route.Method, route.Path)
			}
		} else if route.Authz.Check == checkPublic {
			if op.Security == nil || len(*op.Security) != 0 {
				return fmt.Errorf("public operation %s %s must explicitly declare security: []", route.Method, route.Path)
			}
		} else if _, handlerChecked := handlerChecks[route.Authz.Check]; !handlerChecked {
			// Operation security replaces document defaults. Requirements are OR
			// alternatives, so even one empty object permits anonymous access.
			security := doc.Security
			if op.Security != nil {
				security = *op.Security
			}
			anonymous := len(security) == 0
			for _, requirement := range security {
				anonymous = anonymous || len(requirement) == 0
			}
			if anonymous {
				return fmt.Errorf("protected operation %s %s must require authentication without anonymous alternatives", route.Method, route.Path)
			}
		}
	}
	// Check the reverse direction too: documented operations must not escape coverage.
	missing := []string{}
	for routePath, item := range doc.Paths {
		for _, method := range []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"} {
			if _, exists := item[method]; exists && !covered[method+" "+routePath] {
				missing = append(missing, strings.ToUpper(method)+" "+prefix+routePath)
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("authz contract missing for OpenAPI operations: %s", strings.Join(missing, ", "))
	}
	return nil
}
