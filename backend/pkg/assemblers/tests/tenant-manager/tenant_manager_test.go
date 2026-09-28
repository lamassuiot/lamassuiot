package tenantmanager

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers"
	testassemblers "github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/storage/builder"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const testIssuer = "test-issuer"

type tenantManagerClient struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
}

func (client tenantManagerClient) token(subject string) string {
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": testIssuer, "sub": subject, "aud": "lamassu-test-api",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}).SignedString(client.key)
	require.NoError(client.t, err)
	return token
}

func (client tenantManagerClient) do(subject, method, path string, body any) (int, map[string]any) {
	client.t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		require.NoError(client.t, err)
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, client.server.URL+path, reader)
	require.NoError(client.t, err)
	request.Header.Set("Content-Type", "application/json")
	if subject != "" {
		request.Header.Set("Authorization", "Bearer "+client.token(subject))
	}
	response, err := client.server.Client().Do(request)
	require.NoError(client.t, err)
	defer response.Body.Close()
	payload := map[string]any{}
	raw, err := io.ReadAll(response.Body)
	require.NoError(client.t, err)
	if len(raw) > 0 {
		require.NoError(client.t, json.Unmarshal(raw, &payload), string(raw))
	}
	return response.StatusCode, payload
}

func newTenantManagerTestClient(t *testing.T) tenantManagerClient {
	t.Helper()
	gin.SetMode(gin.TestMode)
	storageConfig, err := testassemblers.PreparePostgresForTest(nil)
	require.NoError(t, err)
	t.Cleanup(storageConfig.AfterSuite)
	require.NoError(t, storageConfig.BeforeEach())

	svc, err := assemblers.AssembleTenantManagerService(config.TenantManagerConfig{
		Logs:         cconfig.Logging{Level: cconfig.Info},
		Storage:      storageConfig.Config,
		Provisioners: []config.TenantManagerProvisioner{{Issuer: testIssuer, Subject: "provisioner"}},
	})
	require.NoError(t, err)

	logger := logrus.NewEntry(logrus.New())
	storageEngine, err := builder.BuildStorageEngine(logger, storageConfig.Config)
	require.NoError(t, err)
	memberships, err := storageEngine.GetControlPlaneMembershipStorage()
	require.NoError(t, err)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	validator := &identityextractors.JWTValidator{
		KeyFunc: func(token *jwt.Token) (interface{}, error) {
			if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
				return nil, errors.New("unexpected JWT signing algorithm")
			}
			return &key.PublicKey, nil
		},
		AllowedIssuers: map[string]struct{}{testIssuer: {}},
		Audience:       "lamassu-test-api",
		AllowedAlgos:   map[string]struct{}{jwt.SigningMethodRS256.Alg(): {}},
	}
	router := routes.NewGinEngine(logger, validator)
	routes.NewTenantManagerHTTPLayer(logger, router.Group("/"), svc, routes.TenantRouteOptions{Memberships: memberships})
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return tenantManagerClient{t: t, server: server, key: key}
}

func TestTenantManagerHTTPLifecycle(t *testing.T) {
	client := newTenantManagerTestClient(t)

	status, _ := client.do("", http.MethodGet, "/api/v2/me/memberships", nil)
	require.Equal(t, http.StatusUnauthorized, status, "requests without JWT are rejected")

	status, _ = client.do("alice", http.MethodPost, "/api/v2/provisioning/organizations", map[string]any{"name": "Acme"})
	require.Equal(t, http.StatusForbidden, status, "only provisioners manage the catalog")

	status, organization := client.do("provisioner", http.MethodPost, "/api/v2/provisioning/organizations", map[string]any{"name": "Acme"})
	require.Equal(t, http.StatusCreated, status)
	organizationID := organization["id"].(string)

	createTenant := func(name, admin string) string {
		status, tenant := client.do("provisioner", http.MethodPost, "/api/v2/provisioning/tenants", map[string]any{
			"organization_id": organizationID, "name": name,
			"initial_admin": map[string]any{"issuer": testIssuer, "subject": admin},
		})
		require.Equal(t, http.StatusCreated, status, tenant)
		return tenant["id"].(string)
	}
	tenantA := createTenant("Plant A", "alice")
	tenantB := createTenant("Plant B", "zoe")

	status, mine := client.do("alice", http.MethodGet, "/api/v2/me/memberships", nil)
	require.Equal(t, http.StatusOK, status)
	require.Len(t, mine["memberships"], 1)
	require.Equal(t, tenantA, mine["memberships"].([]any)[0].(map[string]any)["tenant_id"])

	status, _ = client.do("alice", http.MethodGet, "/api/v2/tenants/"+tenantB+"/memberships", nil)
	require.Equal(t, http.StatusForbidden, status, "no access to tenants without membership")

	status, created := client.do("alice", http.MethodPost, "/api/v2/tenants/"+tenantA+"/invitations", map[string]any{"role": "viewer"})
	require.Equal(t, http.StatusCreated, status, created)
	code := created["code"].(string)
	status, listed := client.do("alice", http.MethodGet, "/api/v2/tenants/"+tenantA+"/invitations", nil)
	require.Equal(t, http.StatusOK, status)
	encodedList, err := json.Marshal(listed)
	require.NoError(t, err)
	require.NotContains(t, string(encodedList), code, "the invitation code is never returned again")

	status, bobMembership := client.do("bob", http.MethodPost, "/api/v2/invitations/"+code+"/accept", nil)
	require.Equal(t, http.StatusCreated, status, bobMembership)
	require.Equal(t, "viewer", bobMembership["role"])
	status, _ = client.do("carol", http.MethodPost, "/api/v2/invitations/"+code+"/accept", nil)
	require.Equal(t, http.StatusConflict, status, "invitations are single use")

	status, _ = client.do("bob", http.MethodPost, "/api/v2/tenants/"+tenantA+"/memberships", map[string]any{
		"issuer": testIssuer, "subject": "mallory", "role": "tenant_admin",
	})
	require.Equal(t, http.StatusForbidden, status, "viewers cannot manage memberships")

	status, carol := client.do("alice", http.MethodPost, "/api/v2/tenants/"+tenantA+"/memberships", map[string]any{
		"issuer": testIssuer, "subject": "carol", "role": "operator",
	})
	require.Equal(t, http.StatusCreated, status, carol)

	status, aliceMemberships := client.do("alice", http.MethodGet, "/api/v2/tenants/"+tenantA+"/memberships", nil)
	require.Equal(t, http.StatusOK, status)
	require.Len(t, aliceMemberships["memberships"], 3)
	var aliceMembershipID string
	for _, item := range aliceMemberships["memberships"].([]any) {
		membership := item.(map[string]any)
		if membership["identity_subject"] == "alice" {
			aliceMembershipID = membership["id"].(string)
		}
	}
	status, _ = client.do("alice", http.MethodPatch, "/api/v2/tenants/"+tenantA+"/memberships/"+aliceMembershipID, map[string]any{"role": "viewer"})
	require.Equal(t, http.StatusConflict, status, "an identity cannot change its own membership")

	status, _ = client.do("alice", http.MethodPatch, "/api/v2/tenants/"+tenantB+"/memberships/"+bobMembership["id"].(string), map[string]any{"role": "viewer"})
	require.Equal(t, http.StatusForbidden, status)

	status, revoked := client.do("alice", http.MethodDelete, "/api/v2/tenants/"+tenantA+"/memberships/"+bobMembership["id"].(string), nil)
	require.Equal(t, http.StatusOK, status, revoked)
	require.Equal(t, "REVOKED", revoked["status"])
	status, bobMine := client.do("bob", http.MethodGet, "/api/v2/me/memberships", nil)
	require.Equal(t, http.StatusOK, status)
	require.Empty(t, bobMine["memberships"])
	status, _ = client.do("bob", http.MethodGet, "/api/v2/tenants/"+tenantA+"/memberships", nil)
	require.Equal(t, http.StatusForbidden, status, "revocation applies to the next request")

	status, _ = client.do("provisioner", http.MethodGet, "/api/v2/tenants/"+tenantA+"/memberships", nil)
	require.Equal(t, http.StatusForbidden, status, "provisioners get no tenant data access")

	status, suspended := client.do("provisioner", http.MethodPut, "/api/v2/provisioning/tenants/"+tenantA+"/status", map[string]any{"status": "SUSPENDED"})
	require.Equal(t, http.StatusOK, status, suspended)
	status, _ = client.do("alice", http.MethodGet, "/api/v2/tenants/"+tenantA+"/memberships", nil)
	require.Equal(t, http.StatusForbidden, status, "suspended tenants reject new operations")
	status, _ = client.do("provisioner", http.MethodPut, "/api/v2/provisioning/tenants/"+tenantA+"/status", map[string]any{"status": "RESTORING"})
	require.Equal(t, http.StatusConflict, status, "lifecycle transitions are enforced")

	status, deleted := client.do("provisioner", http.MethodPut, "/api/v2/provisioning/tenants/"+tenantA+"/status", map[string]any{"status": "DELETED"})
	require.Equal(t, http.StatusOK, status, deleted)
	require.Equal(t, "DELETED", deleted["status"], "suspended tenants are deleted directly")
	status, mine = client.do("alice", http.MethodGet, "/api/v2/me/memberships", nil)
	require.Equal(t, http.StatusOK, status)
	require.Empty(t, mine["memberships"], "deleted tenants are not offered to their members")
	status, _ = client.do("alice", http.MethodGet, "/api/v2/tenants/"+tenantA+"/memberships", nil)
	require.Equal(t, http.StatusForbidden, status, "deleted tenants reject new operations")
}
