package dmsmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/routes"
	authzapi "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/api"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/api/dto"
	authzconfig "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/config"
	authzmodels "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	authzsdk "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/sdk"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Real users with real credentials call the real HTTP layer, and a real authz that loads its schemas as a
// deployment does decides who may grant policies. The other tests call the service in process.
func TestAuthzPrincipalPolicyGrantOverHTTP(t *testing.T) {
	dmsMgr, servers, err := StartDMSManagerServiceTestServer(t)
	require.NoError(t, err)
	ctx := context.Background()

	_, thisFile, _, _ := runtime.Caller(0)
	authzDir := filepath.Join(filepath.Dir(thisFile), "../../../../../connectors/authz")
	dbConfig := maps.Clone(servers.Storage.Config.Config)
	dbConfig["database"], dbConfig["schema"] = "pki", "authz"
	authzDB := cconfig.PluggableStorageEngine{LogLevel: cconfig.Info, Provider: cconfig.Postgres, Config: dbConfig}
	_, _, _, _, port, err := authzapi.AssembleAuthzServiceWithHTTPServer(authzconfig.AuthzConfig{
		Logs:                  cconfig.Logging{Level: cconfig.Info},
		Server:                cconfig.HttpServer{LogLevel: cconfig.Info, Protocol: cconfig.HTTP},
		AuthzDB:               authzDB,
		InsecureSkipJWTVerify: true,
		Schemas:               map[string]string{"authz": filepath.Join(authzDir, "authz.json"), "pki": filepath.Join(authzDir, "pki.json")},
		Credentials:           map[string]cconfig.PluggableStorageEngine{"authz": authzDB, "pki": authzDB},
	}, models.APIServiceInfo{Version: "test", BuildSHA: "-", BuildTime: "-"})
	require.NoError(t, err)
	admin := authzsdk.NewClientWithHTTPClient(sdk.HttpClientWithCustomHeaders(&http.Client{}, "X-Principal-ID", "admin-mode"), fmt.Sprintf("http://127.0.0.1:%d", port))

	rule := func(namespace, schema, entity string, actions ...string) []*authzmodels.Rule {
		return []*authzmodels.Rule{{Namespace: namespace, SchemaName: schema, EntityType: entity, Actions: actions, DirectGrants: []string{"*"}}}
	}
	_, err = admin.Policies.Create(ctx, &dto.CreatePolicyRequest{ID: "manage-ras", Name: "Manage RAs", Rules: rule("pki", "dmsmanager", "dms", "create", "read", "update", "delete")})
	require.NoError(t, err)
	_, err = admin.Policies.Create(ctx, &dto.CreatePolicyRequest{ID: "grant-policies", Name: "Grant policies", Rules: rule("authz", "public", "principal_policy", "grant")})
	require.NoError(t, err)
	user := func(name string, policies ...string) string {
		auth := authzmodels.AuthConfig{"claims": []any{map[string]any{"claim": "sub", "operator": "equals", "value": name}}}
		_, err := admin.Principals.Create(ctx, &dto.CreatePrincipalRequest{ID: "oidc:" + name, Name: name, Type: "oidc", AuthConfig: &auth})
		require.NoError(t, err)
		for _, policyID := range policies {
			require.NoError(t, admin.Principals.GrantPolicy(ctx, "oidc:"+name, &dto.GrantPolicyRequest{PolicyID: policyID, GrantedBy: "test"}))
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": name, "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte("test"))
		require.NoError(t, err)
		return token
	}
	// policy-a and policy-b already exist: the test harness creates them. An operator holds both permissions;
	// an editor may only manage RAs.
	operator, editor := user("operator", "manage-ras", "grant-policies"), user("editor", "manage-ras")
	const internalService = "internal-service"

	logger := logrus.NewEntry(logrus.New())
	router := routes.NewGinEngine(logger)
	authzClient := config.AuthzClient{HTTPClient: cconfig.HTTPClient{HTTPConnection: cconfig.HTTPConnection{Protocol: cconfig.HTTP, BasicConnection: cconfig.BasicConnection{Hostname: "127.0.0.1", Port: port}}}}
	routes.NewDMSManagerHTTPLayer(logger, router.Group("/"), dmsMgr.Service, authzClient)
	srv := httptest.NewServer(router)
	defer srv.Close()

	call := func(token, method, path string, body any) int {
		t.Helper()
		var reader io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			require.NoError(t, err)
			reader = bytes.NewReader(raw)
		}
		req, err := http.NewRequest(method, srv.URL+path, reader)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		if token == internalService {
			req.Header.Set("X-Principal-ID", "admin-mode")
		} else {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
		return res.StatusCode
	}

	ca := createAuthzTestCA(t, servers, "http-ca")
	other := createAuthzTestCA(t, servers, "http-other-ca")
	settings := func(caID string, policies ...string) models.DMSSettings {
		s := authzTestSettings(caID, true)
		s.AuthzPrincipalSettings.PolicyIDs = policies
		return s
	}
	create := func(id string, s models.DMSSettings) map[string]any {
		return map[string]any{"id": id, "name": id, "settings": s}
	}
	update := func(s models.DMSSettings) map[string]any { return map[string]any{"name": "ra-1", "settings": s} }
	granted := func(id string) []string {
		var ids []string
		for policyID := range authzGrants(t, servers, id) {
			ids = append(ids, policyID)
		}
		return ids
	}

	assert.Equal(t, http.StatusForbidden, call(editor, http.MethodPost, "/v1/dms", create("ra-1", settings(ca.ID, "policy-a"))), "an editor may not give a principal policies")
	assert.Nil(t, authzPrincipal(t, servers, "dms:ra-1"), "nothing reached authz")

	assert.Equal(t, http.StatusCreated, call(editor, http.MethodPost, "/v1/dms", create("ra-1", settings(ca.ID))), "a principal without policies grants nothing")
	assert.NotNil(t, authzPrincipal(t, servers, "dms:ra-1"))
	assert.Empty(t, granted("dms:ra-1"))

	assert.Equal(t, http.StatusForbidden, call(editor, http.MethodPut, "/v1/dms/ra-1", update(settings(ca.ID, "policy-a"))), "nor add them later")
	assert.Equal(t, http.StatusOK, call(operator, http.MethodPut, "/v1/dms/ra-1", update(settings(ca.ID, "policy-a"))))
	assert.Equal(t, []string{"policy-a"}, granted("dms:ra-1"))

	assert.Equal(t, http.StatusOK, call(editor, http.MethodPut, "/v1/dms/ra-1", update(settings(ca.ID, "policy-a"))), "saving what is granted already is fine")
	assert.Equal(t, http.StatusForbidden, call(editor, http.MethodPut, "/v1/dms/ra-1", update(settings(other.ID, "policy-a"))), "another Enrollment CA hands the policies to other certificates")
	moved := settings(ca.ID, "policy-a")
	moved.AuthzPrincipalSettings.SubjectAttributeMappings = map[string]string{"device_id": "x509.serial_number"}
	assert.Equal(t, http.StatusForbidden, call(editor, http.MethodPut, "/v1/dms/ra-1", update(moved)), "and so does another mapping")
	assert.Equal(t, http.StatusBadRequest, call(operator, http.MethodPut, "/v1/dms/ra-1", update(settings(ca.ID, "policy-a", "no-such-policy"))), "a policy authz does not know")
	assert.Equal(t, http.StatusOK, call(editor, http.MethodPut, "/v1/dms/ra-1", update(settings(ca.ID))), "taking policies away needs no permission")
	assert.Empty(t, granted("dms:ra-1"))

	assert.Equal(t, http.StatusCreated, call(internalService, http.MethodPost, "/v1/dms", create("ra-2", settings(ca.ID, "policy-a", "policy-b"))), "internal services are trusted")
	assert.ElementsMatch(t, []string{"policy-a", "policy-b"}, granted("dms:ra-2"))
	assert.Equal(t, http.StatusNoContent, call(editor, http.MethodDelete, "/v1/dms/ra-2", nil), "deleting an RA needs no grant permission")
	assert.Nil(t, authzPrincipal(t, servers, "dms:ra-2"), "its principal is gone, with its grants")
}
