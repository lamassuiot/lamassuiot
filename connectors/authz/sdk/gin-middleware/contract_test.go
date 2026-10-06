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
	assert.Contains(t, err.Error(), "protected operation POST /api/ca/v1/certificates must not declare security: []")
}

func TestHandlerAuthorizationContractSupportsProtocolRoutesAndCatchAll(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, kind := range []string{"est", "envoy", "evaluation"} {
		t.Run(kind, func(t *testing.T) {
			router := gin.New()
			contract := NewContractRouter(router.Group("/protocol"))
			called := false
			contract.Handle(http.MethodConnect, "/check/*original_url", HandlerAuthorization(kind), func(c *gin.Context) { called = true; c.Status(204) })
			spec := "openapi: 3.0.3\nservers: [{url: /protocol}]\npaths:\n  /check/{original_url}:\n    x-connect:\n      x-authz: {check: " + kind + "}\n      security: []\n"
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
