//go:build oidc

// Validates the JWT → membership → tenant flow against a real OIDC provider
// (spec 005, task 10.5). Needs a reachable provider with a confidential client
// that can use client credentials:
//
//	OIDC_ISSUER        e.g. https://localhost:8443/realms/lamassu
//	OIDC_CLIENT_ID     client with service accounts enabled
//	OIDC_CLIENT_SECRET its secret
//	OIDC_AUDIENCE      audience added to the access token
//	OIDC_CA_FILE       PEM of the CA that signed the provider's TLS certificate
//
//	CGO_ENABLED=1 go test -tags oidc ./pkg/assemblers/tests/tenant-manager -run TestOIDC -v
package tenantmanager

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
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

func requireEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Skipf("%s is not set", name)
	}
	return value
}

func TestOIDCClientCredentialsReachTenantData(t *testing.T) {
	issuer := requireEnv(t, "OIDC_ISSUER")
	clientID := requireEnv(t, "OIDC_CLIENT_ID")
	clientSecret := requireEnv(t, "OIDC_CLIENT_SECRET")
	audience := requireEnv(t, "OIDC_AUDIENCE")
	caPEM, err := os.ReadFile(requireEnv(t, "OIDC_CA_FILE"))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPEM))
	providerClient := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}

	// Access token from the provider (client credentials).
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}, "client_secret": {clientSecret}}
	tokenResponse, err := providerClient.PostForm(issuer+"/protocol/openid-connect/token", form)
	require.NoError(t, err)
	defer tokenResponse.Body.Close()
	var token struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.NewDecoder(tokenResponse.Body).Decode(&token))
	require.NotEmpty(t, token.AccessToken, "provider returned no access token")
	claims := jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(token.AccessToken, claims)
	require.NoError(t, err)
	subject, _ := claims["sub"].(string)
	require.NotEmpty(t, subject)
	t.Logf("token: iss=%v sub=%s aud=%v scope=%v", claims["iss"], subject, claims["aud"], claims["scope"])

	// Backend configured exactly as in a deployment: issuer allowlist, JWKS
	// over HTTPS, audience and algorithms.
	validator, err := identityextractors.NewJWTValidator(cconfig.HttpServerJWTAuthentication{
		Enabled:           true,
		Audience:          audience,
		IssuerJWKSURLs:    map[string]string{issuer: issuer + "/protocol/openid-connect/certs"},
		AllowedAlgorithms: []string{"RS256"},
		JWKSCacheTTL:      time.Minute,
	}, providerClient)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	storageConfig, err := testassemblers.PreparePostgresForTest(nil)
	require.NoError(t, err)
	t.Cleanup(storageConfig.AfterSuite)
	require.NoError(t, storageConfig.BeforeEach())
	svc, err := assemblers.AssembleTenantManagerService(config.TenantManagerConfig{
		Logs:         cconfig.Logging{Level: cconfig.Info},
		Storage:      storageConfig.Config,
		Provisioners: []config.TenantManagerProvisioner{{Issuer: issuer, Subject: subject}},
	})
	require.NoError(t, err)
	logger := logrus.NewEntry(logrus.New())
	storageEngine, err := builder.BuildStorageEngine(logger, storageConfig.Config)
	require.NoError(t, err)
	memberships, err := storageEngine.GetControlPlaneMembershipStorage()
	require.NoError(t, err)
	router := routes.NewGinEngine(logger, validator)
	routes.NewTenantManagerHTTPLayer(logger, router.Group("/"), svc, routes.TenantRouteOptions{Memberships: memberships})
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	call := func(bearer, method, path string, body any) (int, map[string]any) {
		var reader io.Reader
		if body != nil {
			encoded, _ := json.Marshal(body)
			reader = bytes.NewReader(encoded)
		}
		request, err := http.NewRequest(method, server.URL+path, reader)
		require.NoError(t, err)
		request.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		response, err := server.Client().Do(request)
		require.NoError(t, err)
		defer response.Body.Close()
		payload := map[string]any{}
		_ = json.NewDecoder(response.Body).Decode(&payload)
		return response.StatusCode, payload
	}

	status, organization := call(token.AccessToken, http.MethodPost, "/api/v2/provisioning/organizations", map[string]any{"name": "OIDC Org"})
	require.Equal(t, http.StatusCreated, status, organization)
	status, tenant := call(token.AccessToken, http.MethodPost, "/api/v2/provisioning/tenants", map[string]any{
		"organization_id": organization["id"], "name": "OIDC Tenant",
		"initial_admin": map[string]any{"issuer": issuer, "subject": subject},
	})
	require.Equal(t, http.StatusCreated, status, tenant)
	tenantID := tenant["id"].(string)

	status, mine := call(token.AccessToken, http.MethodGet, "/api/v2/me/memberships", nil)
	require.Equal(t, http.StatusOK, status)
	require.Len(t, mine["memberships"], 1, "the provider identity (iss, sub) resolves to its membership")

	status, list := call(token.AccessToken, http.MethodGet, "/api/v2/tenants/"+tenantID+"/memberships", nil)
	require.Equal(t, http.StatusOK, status, "a real provider token with standard OIDC scopes must reach tenant data: %v", list)

	tampered := token.AccessToken[:len(token.AccessToken)-4] + strings.Repeat("A", 4)
	status, _ = call(tampered, http.MethodGet, "/api/v2/me/memberships", nil)
	require.Equal(t, http.StatusUnauthorized, status, "a token with an invalid signature is rejected")
	status, _ = call(token.AccessToken, http.MethodGet, "/api/v2/tenants/00000000-0000-0000-0000-0000000000ff/memberships", nil)
	require.Equal(t, http.StatusForbidden, status, "no access to a tenant without membership")
}
