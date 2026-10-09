package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	authzschemas "github.com/lamassuiot/authz"
	authzsdk "github.com/lamassuiot/authz/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func certificateMiddleware(t *testing.T, engine *fakeEngine) *AuthzMiddleware {
	t.Helper()
	schemas, err := authzschemas.PKISchemas()
	require.NoError(t, err)
	return MustNewAuthzMiddleware(engine, schemas, "pki", "ca", "certificate", testLogger())
}

func TestCertificateCreateRejectsInvalidDeclarationsBeforeServing(t *testing.T) {
	schemas, err := authzschemas.PKISchemas()
	require.NoError(t, err)
	for _, test := range []struct {
		name        string
		declaration func()
		message     string
	}{
		{"unknown action", func() { certificateMiddleware(t, &fakeEngine{}).Global("cretae") }, `action "cretae"`},
		{"existing check API", func() { certificateMiddleware(t, &fakeEngine{}).AuthzCheck("cretae") }, `action "cretae"`},
		{"atomic action as global", func() { certificateMiddleware(t, &fakeEngine{}).Global("read") }, `is not global`},
		{"unknown entity", func() { MustNewAuthzMiddleware(&fakeEngine{}, schemas, "pki", "ca", "certificat", testLogger()) }, `certificat`},
		{"wrong namespace", func() { MustNewAuthzMiddleware(&fakeEngine{}, schemas, "other", "ca", "certificate", testLogger()) }, `namespace "other"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				value := recover()
				require.NotNil(t, value, "declaration did not panic during registration")
				assert.Contains(t, fmt.Sprint(value), test.message)
			}()
			test.declaration()
		})
	}
	// Editing the actual loaded schema also invalidates registration.
	definition, err := schemas.GetBySchemaEntity("ca", "certificate")
	require.NoError(t, err)
	definition.GlobalActions = []string{"import"}
	mw := MustNewAuthzMiddleware(&fakeEngine{}, schemas, "pki", "ca", "certificate", testLogger())
	assert.Panics(t, func() { mw.Global("create") })
}

type recordingCreateEngine struct {
	fakeEngine
	declaration Declaration
	entityKey   map[string]string
	calls       int
}

func (e *recordingCreateEngine) MatchAndAuthorize(_ context.Context, _, _, namespace, schemaName, action, entityType string, key map[string]string) (bool, []string, error) {
	e.calls++
	e.declaration = Declaration{Namespace: namespace, SchemaName: schemaName, EntityType: entityType, Action: action}
	e.entityKey = key
	return e.authorized, nil, nil
}

func TestCertificateCreateRecordedContractMatchesEnforcedPermission(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		t.Run(fmt.Sprintf("allowed=%v", allowed), func(t *testing.T) {
			router := testRouterWithAuthzInputs()
			engine := &recordingCreateEngine{fakeEngine: fakeEngine{authorized: allowed}}
			schemas, err := authzschemas.PKISchemas()
			require.NoError(t, err)
			mw := MustNewAuthzMiddleware(engine, schemas, "pki", "ca", "certificate", testLogger())
			contract := NewContractRouter(router.Group("/api/ca/v1"))
			called := false
			contract.Handle(http.MethodPost, "/certificates", mw.Global("create"), func(c *gin.Context) { called = true; c.Status(http.StatusCreated) })
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/ca/v1/certificates", nil))
			expected := http.StatusForbidden
			if allowed {
				expected = http.StatusCreated
			}
			assert.Equal(t, expected, response.Code)
			assert.Equal(t, allowed, called)
			assert.Equal(t, 1, engine.calls)
			require.Len(t, contract.Declarations(), 1)
			assert.Equal(t, contract.Declarations()[0].Authz, engine.declaration)
			assert.Nil(t, engine.entityKey, "global create must not fabricate an empty entity key")
		})
	}
}

func TestCertificateCreateOpenAPIContractRejectsDrift(t *testing.T) {
	router := testRouterWithAuthzInputs()
	contract := NewContractRouter(router.Group("/api/ca/v1"))
	contract.Handle(http.MethodPost, "/certificates", certificateMiddleware(t, &fakeEngine{}).Global("create"), func(*gin.Context) {})
	spec := `openapi: 3.0.3
servers:
  - url: /api/ca/v1
components:
  securitySchemes:
    BearerAuth: {type: http, scheme: bearer}
security:
  - BearerAuth: []
paths:
  /certificates:
    parameters: []
    post:
      x-authz:
        namespace: pki
        schema_name: ca
        entity_type: certificate
        action: create
`
	require.NoError(t, contract.ValidateOpenAPI(strings.NewReader(spec)))
	for _, test := range []struct {
		name              string
		old, new, message string
	}{
		{"valid but incorrect action", "action: create", "action: import", "contract mismatch"},
		{"unknown action", "action: create", "action: cretae", "contract mismatch"},
		{"wrong entity", "entity_type: certificate", "entity_type: ca_certificate", "contract mismatch"},
		{"wrong namespace", "namespace: pki", "namespace: other", "contract mismatch"},
		{"wrong schema", "schema_name: ca", "schema_name: other", "contract mismatch"},
		{"wrong method", "    post:", "    get:", "operation missing"},
		{"wrong path", "  /certificates:", "  /certificates/import:", "operation missing"},
		{"wrong prefix", "url: /api/ca/v1", "url: /api/ca/v2", "does not match"},
		{"missing extension", "      x-authz:", "      x-other:", "x-authz missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := contract.ValidateOpenAPI(strings.NewReader(strings.Replace(spec, test.old, test.new, 1)))
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.message)
		})
	}
	assert.Panics(t, func() { contract.Handle(http.MethodPost, "/unguarded", Permission{}, func(*gin.Context) {}) })
}

func TestResourcePermissionValidatesAndExtractsSchemaKeys(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		t.Run(fmt.Sprintf("allowed=%v", allowed), func(t *testing.T) {
			router := testRouterWithAuthzInputs()
			engine := &recordingCreateEngine{fakeEngine: fakeEngine{authorized: allowed}}
			schemas, err := authzschemas.PKISchemas()
			require.NoError(t, err)
			mw := MustNewAuthzMiddleware(engine, schemas, "pki", "ca", "certificate", testLogger())
			binding := map[string]string{"serial_number": "sn"}
			permission := mw.Resource("read", binding)
			binding["serial_number"] = "id" // caller mutation must not change enforcement
			contract := NewContractRouter(router.Group("/api/ca/v1"))
			called := false
			contract.Handle(http.MethodGet, "/cas/:id/certificates/:sn", permission, func(c *gin.Context) { called = true; c.Status(http.StatusOK) })
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/ca/v1/cas/ca-1/certificates/cert-2", nil))
			expected := http.StatusForbidden
			if allowed {
				expected = http.StatusOK
			}
			assert.Equal(t, expected, response.Code)
			assert.Equal(t, allowed, called)
			assert.Equal(t, map[string]string{"serial_number": "cert-2"}, engine.entityKey)
			assert.Equal(t, contract.Declarations()[0].Authz, engine.declaration)
		})
	}
}

func TestResourcePermissionRejectsInvalidBindingsBeforeServing(t *testing.T) {
	mw := certificateMiddleware(t, &fakeEngine{})
	assert.Panics(t, func() { mw.Resource("create", map[string]string{"serial_number": "sn"}) })
	assert.Panics(t, func() { mw.Resource("reed", map[string]string{"serial_number": "sn"}) })
	assert.Panics(t, func() { mw.Resource("read", nil) })
	assert.Panics(t, func() { mw.Resource("read", map[string]string{"id": "sn"}) })
	assert.Panics(t, func() { mw.Resource("read", map[string]string{"serial_number": "sn", "id": "id"}) })
	router := testRouterWithAuthzInputs()
	contract := NewContractRouter(router.Group("/api/ca/v1"))
	assert.Panics(t, func() {
		contract.Handle(http.MethodGet, "/certificates/:id", mw.Resource("read", map[string]string{"serial_number": "sn"}), func(*gin.Context) {})
	})
	assert.Empty(t, router.Routes(), "invalid declarations must fail before route registration")
}

func TestResourcePermissionRejectsDuplicateParamBindingsForCompositeKeys(t *testing.T) {
	schemas, err := authzschemas.PKISchemas()
	require.NoError(t, err)
	mw := MustNewAuthzMiddleware(&fakeEngine{}, schemas, "pki", "kms", "kms_key", testLogger())
	require.Len(t, mw.definition.PrimaryKeys, 2)
	assert.PanicsWithValue(t,
		fmt.Sprintf("authz path parameter %q is bound to both primary keys %q and %q", "id", mw.definition.PrimaryKeys[0], mw.definition.PrimaryKeys[1]),
		func() {
			mw.Resource("read", map[string]string{mw.definition.PrimaryKeys[0]: "id", mw.definition.PrimaryKeys[1]: "id"})
		})
	assert.NotPanics(t, func() {
		mw.Resource("read", map[string]string{mw.definition.PrimaryKeys[0]: "key", mw.definition.PrimaryKeys[1]: "engine"})
	})
}

func TestListPermissionPropagatesFilterAndRecordsItsContract(t *testing.T) {
	router := testRouterWithAuthzInputs()
	engine := &fakeEngine{filterSQL: "serial_number = 'cert-2'"}
	mw := certificateMiddleware(t, engine)
	contract := NewContractRouter(router.Group("/api/ca/v1"))
	contract.Handle(http.MethodGet, "/certificates", mw.List(), func(c *gin.Context) {
		assert.Equal(t, engine.filterSQL, c.Request.Context().Value(authzsdk.AuthzQueryKey))
		assert.Equal(t, engine.filterSQL, c.GetString("authz_query"))
		c.Status(http.StatusOK)
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/ca/v1/certificates", nil))
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, Declaration{Namespace: "pki", SchemaName: "ca", EntityType: "certificate", Check: "filter"}, contract.Declarations()[0].Authz)
	schemas, err := authzschemas.PKISchemas()
	require.NoError(t, err)
	definition, err := schemas.GetBySchemaEntity("ca", "certificate")
	require.NoError(t, err)
	definition.AtomicActions = []string{"delete"}
	assert.Panics(t, func() { MustNewAuthzMiddleware(engine, schemas, "pki", "ca", "certificate", testLogger()).List() })
}

func TestContractRequiresEveryOpenAPIOperationAndRegisteredRoute(t *testing.T) {
	router := testRouterWithAuthzInputs()
	contract := NewContractRouter(router.Group("/api/ca/v1"))
	contract.Handle(http.MethodPost, "/certificates", certificateMiddleware(t, &fakeEngine{}).Global("create"), func(*gin.Context) {})
	spec := `openapi: 3.0.3
servers:
  - url: /api/ca/v1
components:
  securitySchemes:
    BearerAuth: {type: http, scheme: bearer}
security:
  - BearerAuth: []
paths:
  /certificates:
    post:
      x-authz:
        namespace: pki
        schema_name: ca
        entity_type: certificate
        action: create
`
	require.NoError(t, contract.ValidateOpenAPI(strings.NewReader(spec)))
	require.NoError(t, contract.ValidateRoutes(router.Routes()))
	for _, method := range []string{"get", "put", "post", "delete", "patch", "head", "options", "trace"} {
		t.Run(method, func(t *testing.T) {
			extra := spec + "  /uncovered:\n    " + method + ":\n      responses: {}\n"
			err := contract.ValidateOpenAPI(strings.NewReader(extra))
			require.Error(t, err)
			assert.Contains(t, err.Error(), strings.ToUpper(method)+" /api/ca/v1/uncovered")
		})
	}
	// An empty registry must not silently accept a nonempty OpenAPI document.
	empty := NewContractRouter(router.Group("/empty"))
	require.Error(t, empty.ValidateOpenAPI(strings.NewReader(spec)))
	require.Error(t, contract.ValidateRoutes(nil))
	router.GET("/unrelated", func(*gin.Context) {})
	require.NoError(t, contract.ValidateRoutes(router.Routes()))
	router.GET("/api/ca/v1/untracked", func(*gin.Context) {})
	err := contract.ValidateRoutes(router.Routes())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GET /api/ca/v1/untracked")
}

func TestContractGroupsAndVerbHelpersRecordIntoOneContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	certs := certificateMiddleware(t, &fakeEngine{authorized: true})
	snKey := map[string]string{"serial_number": "sn"}
	handler := func(*gin.Context) {}

	contract := NewContractRouter(router.Group("/api/ca"))
	contract.GET("/health", Public(), handler)
	v1 := contract.Group("/v1")
	v1.GET("/certificates", certs.List(), handler)
	v1.POST("/certificates", certs.Global("create"), handler)
	v1.PUT("/certificates/:sn/status", certs.Resource("status-update", snKey), handler)
	v1.PATCH("/certificates/:sn/metadata", certs.Resource("metadata-update", snKey), handler)
	v1.DELETE("/certificates/:sn", certs.Resource("delete", snKey), handler)

	// The root sees sub-router routes; each router validates only its own group.
	declared := map[string]bool{}
	for _, route := range contract.Declarations() {
		declared[route.Method+" "+route.Path] = true
	}
	assert.Equal(t, map[string]bool{
		"GET /api/ca/health":                         true,
		"GET /api/ca/v1/certificates":                true,
		"POST /api/ca/v1/certificates":               true,
		"PUT /api/ca/v1/certificates/:sn/status":     true,
		"PATCH /api/ca/v1/certificates/:sn/metadata": true,
		"DELETE /api/ca/v1/certificates/:sn":         true,
	}, declared)
	assert.Len(t, v1.Declarations(), len(contract.Declarations()))
	require.NoError(t, contract.ValidateRoutes(router.Routes()))
	require.NoError(t, v1.ValidateRoutes(router.Routes()))

	router.GET("/api/ca/v1/untracked", handler)
	for _, validator := range []*ContractRouter{contract, v1} {
		err := validator.ValidateRoutes(router.Routes())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "GET /api/ca/v1/untracked")
	}
}

func TestCustomResourcePermissionChecksCompositeKeysBeforeAuthorization(t *testing.T) {
	for _, test := range []struct {
		name           string
		key            map[string]string
		allowed, abort bool
		status         int
		calls          int
	}{
		{name: "allowed", key: map[string]string{"key_id": "key-1", "engine_id": "engine-2"}, allowed: true, status: http.StatusOK, calls: 1},
		{name: "denied", key: map[string]string{"key_id": "key-1", "engine_id": "engine-2"}, status: http.StatusForbidden, calls: 1},
		{name: "nil key", status: http.StatusBadRequest},
		{name: "missing engine", key: map[string]string{"key_id": "key-1"}, status: http.StatusBadRequest},
		{name: "empty engine", key: map[string]string{"key_id": "key-1", "engine_id": ""}, status: http.StatusBadRequest},
		{name: "wrong column", key: map[string]string{"key_id": "key-1", "id": "engine-2"}, status: http.StatusBadRequest},
		{name: "extra column", key: map[string]string{"key_id": "key-1", "engine_id": "engine-2", "id": "other"}, status: http.StatusBadRequest},
		{name: "extractor aborted", abort: true, status: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := testRouterWithAuthzInputs()
			engine := &recordingCreateEngine{fakeEngine: fakeEngine{authorized: test.allowed}}
			schemas, err := authzschemas.PKISchemas()
			require.NoError(t, err)
			mw := MustNewAuthzMiddleware(engine, schemas, "pki", "kms", "kms_key", testLogger())
			contract := NewContractRouter(router.Group("/api/kms/v1"))
			called := false
			permission := mw.ResourceCustom("read", "id", func(c *gin.Context) map[string]string {
				assert.Equal(t, "alias-1", c.Param("id"))
				if test.abort {
					c.AbortWithStatus(http.StatusForbidden)
				}
				return test.key
			})
			contract.Handle(http.MethodGet, "/keys/:id", permission, func(c *gin.Context) { called = true; c.Status(http.StatusOK) })
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/kms/v1/keys/alias-1", nil))
			assert.Equal(t, test.status, response.Code)
			assert.Equal(t, test.calls, engine.calls)
			assert.Equal(t, test.allowed, called)
			if test.calls > 0 {
				assert.Equal(t, test.key, engine.entityKey)
				assert.Equal(t, contract.Declarations()[0].Authz, engine.declaration)
			}
		})
	}
}

func TestCustomResourcePermissionRejectsInvalidDeclarationsBeforeServing(t *testing.T) {
	schemas, err := authzschemas.PKISchemas()
	require.NoError(t, err)
	mw := MustNewAuthzMiddleware(&fakeEngine{}, schemas, "pki", "kms", "kms_key", testLogger())
	extractor := func(*gin.Context) map[string]string { return nil }
	assert.Panics(t, func() { mw.ResourceCustom("create", "id", extractor) })
	assert.Panics(t, func() { mw.ResourceCustom("reed", "id", extractor) })
	assert.Panics(t, func() { mw.ResourceCustom("read", "id", nil) })
	assert.Panics(t, func() { mw.ResourceCustom("read", "", extractor) })
	router := testRouterWithAuthzInputs()
	contract := NewContractRouter(router.Group("/api/kms/v1"))
	assert.Panics(t, func() {
		contract.Handle(http.MethodGet, "/keys/:key", mw.ResourceCustom("read", "id", extractor), func(*gin.Context) {})
	})
	assert.Empty(t, router.Routes())
}

func TestPublicPermissionWorksWithoutAuthenticationAndRequiresExplicitOpenAPISecurity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	contract := NewContractRouter(router.Group("/api/va"))
	called := false
	contract.Handle(http.MethodGet, "/crl/:ca-ski", Public(), func(c *gin.Context) { called = true; c.Status(http.StatusOK) })
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/va/crl/ca-1", nil))
	assert.Equal(t, http.StatusOK, response.Code)
	assert.True(t, called)
	spec := `openapi: 3.0.3
servers:
  - url: /api/va
components:
  securitySchemes:
    BearerAuth: {type: http, scheme: bearer}
security:
  - BearerAuth: []
paths:
  /crl/{ca-ski}:
    get:
      x-authz:
        check: public
      security: []
`
	require.NoError(t, contract.ValidateOpenAPI(strings.NewReader(spec)))
	for _, security := range []string{"", "      security: null", "      security: [{BearerAuth: []}]"} {
		wrong := strings.Replace(spec, "      security: []", security, 1)
		err := contract.ValidateOpenAPI(strings.NewReader(wrong))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must explicitly declare security: []")
	}
}

func TestProtectedPermissionRejectsAnonymousOpenAPISecurity(t *testing.T) {
	router := testRouterWithAuthzInputs()
	contract := NewContractRouter(router.Group("/api/ca/v1"))
	contract.Handle(http.MethodPost, "/certificates", certificateMiddleware(t, &fakeEngine{}).Global("create"), func(*gin.Context) {})
	spec := `openapi: 3.0.3
servers:
  - url: /api/ca/v1
components:
  securitySchemes:
    BearerAuth: {type: http, scheme: bearer}
security:
  - BearerAuth: []
paths:
  /certificates:
    post:
      x-authz:
        namespace: pki
        schema_name: ca
        entity_type: certificate
        action: create
      security: []
`
	err := contract.ValidateOpenAPI(strings.NewReader(spec))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "protected operation POST /api/ca/v1/certificates must require authentication without anonymous alternatives")
}

func TestHandlerAuthorizationContractSupportsProtocolRoutesAndCatchAll(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// Every registered handler check must validate as a protocol route.
	for kind := range handlerChecks {
		t.Run(kind, func(t *testing.T) {
			router := gin.New()
			contract := NewContractRouter(router.Group("/protocol"))
			called := false
			permission := HandlerAuthorization(kind)
			boundary := ""
			if handlerChecks[kind] {
				boundary = "internal-service"
				permission = permission.WithTrustBoundary(boundary)
			}
			contract.Handle(http.MethodConnect, "/check/*original_url", permission, func(c *gin.Context) { called = true; c.Status(204) })
			spec := "openapi: 3.0.3\nservers: [{url: /protocol}]\npaths:\n  /check/{original_url}:\n    x-connect:\n      x-authz: {check: " + kind + "}\n      security: []\n"
			if boundary != "" {
				spec += "      x-trust-boundary: " + boundary + "\n"
			}
			require.NoError(t, contract.ValidateOpenAPI(strings.NewReader(spec)))
			require.NoError(t, contract.ValidateRoutes(router.Routes()))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodConnect, "/protocol/check/a/b", nil))
			assert.Equal(t, 204, response.Code)
			assert.True(t, called)
			wrong := strings.Replace(spec, "check: "+kind, "check: public", 1)
			assert.Error(t, contract.ValidateOpenAPI(strings.NewReader(wrong)))
			extra := spec + "  /uncovered:\n    x-connect:\n      responses: {}\n"
			assert.ErrorContains(t, contract.ValidateOpenAPI(strings.NewReader(extra)), "CONNECT /protocol/uncovered")
		})
	}
	assert.Panics(t, func() { HandlerAuthorization("typo") })
}

func TestProtectedPermissionResolvesOpenAPISecurity(t *testing.T) {
	router := testRouterWithAuthzInputs()
	contract := NewContractRouter(router.Group("/api/ca/v1"))
	contract.Handle(http.MethodPost, "/certificates", certificateMiddleware(t, &fakeEngine{}).Global("create"), func(*gin.Context) {})
	for _, test := range []struct {
		name, document, operation string
		allowed                   bool
	}{
		{name: "no security declared"},
		{name: "empty document security", document: "[]"},
		{name: "anonymous document option", document: "[{}]"},
		{name: "optional document authentication", document: "[{BearerAuth: []}, {}]"},
		{name: "inherited authentication", document: "[{BearerAuth: []}]", allowed: true},
		{name: "operation authentication", operation: "[{BearerAuth: []}]", allowed: true},
		{name: "operation overrides anonymous document", document: "[{}]", operation: "[{BearerAuth: []}]", allowed: true},
		{name: "operation overrides empty document", document: "[]", operation: "[{BearerAuth: []}]", allowed: true},
		{name: "operation overrides different scheme", document: "[{ApiKeyAuth: []}]", operation: "[{BearerAuth: []}]", allowed: true},
		{name: "empty operation removes inherited authentication", document: "[{BearerAuth: []}]", operation: "[]"},
		{name: "anonymous operation overrides authentication", document: "[{BearerAuth: []}]", operation: "[{}]"},
		{name: "optional operation authentication", document: "[{BearerAuth: []}]", operation: "[{BearerAuth: []}, {}]"},
		{name: "anonymous alternative first", operation: "[{}, {BearerAuth: []}]"},
		{name: "authenticated alternatives", document: "[{BearerAuth: []}, {ApiKeyAuth: []}]", allowed: true},
		{name: "combined authenticated requirements", operation: "[{BearerAuth: [], ApiKeyAuth: []}]", allowed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := "openapi: 3.0.3\nservers: [{url: /api/ca/v1}]\n" +
				"components: {securitySchemes: {BearerAuth: {type: http, scheme: bearer}, ApiKeyAuth: {type: apiKey, in: header, name: X-API-Key}}}\n"
			if test.document != "" {
				spec += "security: " + test.document + "\n"
			}
			spec += "paths:\n  /certificates:\n    post:\n      x-authz: {namespace: pki, schema_name: ca, entity_type: certificate, action: create}\n"
			if test.operation != "" {
				spec += "      security: " + test.operation + "\n"
			}
			err := contract.ValidateOpenAPI(strings.NewReader(spec))
			if test.allowed {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "protected operation POST /api/ca/v1/certificates must require authentication without anonymous alternatives")
			}
		})
	}
}

func TestOpenAPISecurityMustReferenceDefinedSchemes(t *testing.T) {
	router := testRouterWithAuthzInputs()
	contract := NewContractRouter(router.Group("/api/ca/v1"))
	contract.Handle(http.MethodPost, "/certificates", certificateMiddleware(t, &fakeEngine{}).Global("create"), func(*gin.Context) {})
	for _, test := range []struct {
		name, components, document, operation, message string
	}{
		{name: "operation typo", components: "{BearerAuth: {type: http, scheme: bearer}}", operation: "[{BearerAuht: []}]", message: `scheme "BearerAuht" for POST /api/ca/v1/certificates`},
		{name: "inherited undefined scheme", components: "{ApiKeyAuth: {type: apiKey, in: header, name: X-API-Key}}", document: "[{BearerAuth: []}]", message: `scheme "BearerAuth" is not defined`},
		{name: "no components", document: "[{BearerAuth: []}]", message: `scheme "BearerAuth" is not defined`},
		{name: "one undefined scheme in a combined requirement", components: "{BearerAuth: {type: http, scheme: bearer}}", operation: "[{BearerAuth: [], ApiKeyAuth: []}]", message: `scheme "ApiKeyAuth"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := "openapi: 3.0.3\nservers: [{url: /api/ca/v1}]\n"
			if test.components != "" {
				spec += "components: {securitySchemes: " + test.components + "}\n"
			}
			if test.document != "" {
				spec += "security: " + test.document + "\n"
			}
			spec += "paths:\n  /certificates:\n    post:\n      x-authz: {namespace: pki, schema_name: ca, entity_type: certificate, action: create}\n"
			if test.operation != "" {
				spec += "      security: " + test.operation + "\n"
			}
			require.ErrorContains(t, contract.ValidateOpenAPI(strings.NewReader(spec)), test.message)
		})
	}
}

func TestTrustBoundaryIsPublicUntilEnforcementIsConfigured(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	contract := NewContractRouter(router.Group("/boundary"))
	permission := Public().WithTrustBoundary("internal-gateway")
	contract.Handle(http.MethodGet, "/check", permission, func(c *gin.Context) { c.Status(204) })
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/boundary/check", nil))
	require.Equal(t, 204, response.Code, "trust boundaries currently do not authenticate callers")
	require.Equal(t, "internal-gateway", contract.Declarations()[0].TrustBoundary)
	spec := `openapi: 3.0.3
servers: [{url: /boundary}]
components: {securitySchemes: {BearerAuth: {type: http, scheme: bearer}}}
security: [{BearerAuth: []}]
paths:
  /check:
    get:
      x-authz: {check: public}
      x-trust-boundary: internal-gateway
      security: []
`
	require.NoError(t, contract.ValidateOpenAPI(strings.NewReader(spec)))
	for _, test := range []struct{ name, old, replacement, error string }{
		{"missing boundary", "      x-trust-boundary: internal-gateway", "", "trust boundary mismatch"},
		{"different boundary", "internal-gateway", "internal-service", "trust boundary mismatch"},
		{"inherited authentication", "      security: []", "", "while enforcement is not configured"},
		{"claimed authentication", "security: []", "security: [{BearerAuth: []}]", "while enforcement is not configured"},
		{"implicit anonymous access", "security: []", "security: [{}]", "must explicitly declare security: []"},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.ErrorContains(t, contract.ValidateOpenAPI(strings.NewReader(strings.Replace(spec, test.old, test.replacement, 1))), test.error)
		})
	}
	assert.Panics(t, func() { Public().WithTrustBoundary("typo") })
	assert.Panics(t, func() { certificateMiddleware(t, &fakeEngine{}).Global("create").WithTrustBoundary("internal-service") })
	for kind, requiresBoundary := range handlerChecks {
		if !requiresBoundary {
			continue
		}
		assert.Panics(t, func() {
			contract.Handle(http.MethodPost, "/missing-"+kind, HandlerAuthorization(kind), func(*gin.Context) {})
		})
	}
	plain := NewContractRouter(gin.New().Group("/boundary"))
	plain.Handle(http.MethodGet, "/check", Public(), func(*gin.Context) {})
	require.ErrorContains(t, plain.ValidateOpenAPI(strings.NewReader(spec)), "trust boundary mismatch")
}

func TestContractBindsResourcesToCatchAllParameters(t *testing.T) {
	router := testRouterWithAuthzInputs()
	engine := &recordingCreateEngine{fakeEngine: fakeEngine{authorized: true}}
	schemas, err := authzschemas.PKISchemas()
	require.NoError(t, err)
	mw := MustNewAuthzMiddleware(engine, schemas, "pki", "kms", "kms_key", testLogger())
	contract := NewContractRouter(router.Group("/api/kms/v1"))
	key := map[string]string{"key_id": "key-1", "engine_id": "engine-2"}
	permission := mw.ResourceCustom("read", "uri", func(c *gin.Context) map[string]string {
		assert.Equal(t, "/pkcs11/token/key-1", c.Param("uri"))
		return key
	})
	require.NotPanics(t, func() {
		contract.GET("/keys/*uri", permission, func(c *gin.Context) { c.Status(http.StatusOK) })
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/kms/v1/keys/pkcs11/token/key-1", nil))
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, key, engine.entityKey)
	assert.Panics(t, func() {
		contract.GET("/aliases/*alias", mw.ResourceCustom("read", "uri", func(*gin.Context) map[string]string { return key }), func(*gin.Context) {})
	})
}

func TestContractRecordsTheExactPathGinRegisters(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := func(*gin.Context) {}
	for _, test := range []struct{ base, relative, expected string }{
		{base: "/api/", relative: "", expected: "/api/"},
		{base: "/api", relative: "", expected: "/api"},
		{base: "/api", relative: "/", expected: "/api/"},
		{base: "/api/", relative: "/items/", expected: "/api/items/"},
		{base: "/api", relative: "items", expected: "/api/items"},
		{base: "/", relative: "", expected: "/"},
	} {
		t.Run(test.base+"+"+test.relative, func(t *testing.T) {
			router := gin.New()
			contract := NewContractRouter(router.Group(test.base))
			contract.GET(test.relative, Public(), handler)
			require.Len(t, router.Routes(), 1)
			assert.Equal(t, test.expected, router.Routes()[0].Path)
			assert.Equal(t, test.expected, contract.Declarations()[0].Path)
			require.NoError(t, contract.ValidateRoutes(router.Routes()))
		})
	}
}

func TestOpenAPIRootPathMatchesARouteAtTheServerURL(t *testing.T) {
	gin.SetMode(gin.TestMode)
	contract := NewContractRouter(gin.New().Group("/api/va"))
	contract.GET("", Public(), func(*gin.Context) {})
	spec := "openapi: 3.0.3\nservers: [{url: /api/va}]\npaths:\n  /:\n    get:\n      x-authz: {check: public}\n      security: []\n"
	require.NoError(t, contract.ValidateOpenAPI(strings.NewReader(spec)))
	undocumented := strings.Replace(spec, "  /:\n", "  /other:\n", 1)
	require.ErrorContains(t, contract.ValidateOpenAPI(strings.NewReader(undocumented)), "OpenAPI operation missing for GET /api/va")
}
