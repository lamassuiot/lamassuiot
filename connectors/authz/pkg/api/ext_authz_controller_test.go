package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/engine"
	"github.com/lamassuiot/authz/pkg/models"
	"github.com/lamassuiot/authz/pkg/service"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtAuthzCheck_AllowsEnvoyHTTPServiceRequest(t *testing.T) {
	router := testExtAuthzRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/ext_authz/check", nil)
	req.Header.Set("authorization", "Bearer good")
	req.Header.Set("x-envoy-original-path", "/api/v1/resource")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "principal-1", rec.Header().Get("x-current-user"))
	assert.Empty(t, rec.Body.String())
}

func TestExtAuthzCheck_DeniesMissingCredentialLikeEnvoyExample(t *testing.T) {
	router := testExtAuthzRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/ext_authz/check", nil)
	req.Header.Set("x-envoy-original-path", "/api/v1/resource")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Empty(t, rec.Body.String())
}

func TestExtAuthzCheck_DeniesWhenNoFineGrainedHTTPActionGrantsRoute(t *testing.T) {
	router := testExtAuthzRouter(t)

	req := httptest.NewRequest(http.MethodDelete, "/ext_authz/check", nil)
	req.Header.Set("authorization", "Bearer good")
	req.Header.Set("x-envoy-original-path", "/api/v1/resource")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Empty(t, rec.Header().Get("x-current-user"))
	assert.Empty(t, rec.Body.String())
}

func TestExtAuthzCheck_LogsDecisionDetails(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetFormatter(&logrus.JSONFormatter{})
	router := testExtAuthzRouterWithLogger(t, logrus.NewEntry(logger))

	req := httptest.NewRequest(http.MethodGet, "/ext_authz/check", nil)
	req.Header.Set("authorization", "Bearer good")
	req.Header.Set("x-envoy-original-path", "/api/v1/resource")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var fields map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &fields))
	assert.Equal(t, "GET", fields["ext_authz_method"])
	assert.Equal(t, "/ext_authz/check", fields["ext_authz_incoming_url"])
	assert.Equal(t, "/api/v1/resource", fields["ext_authz_path"])
	assert.Equal(t, "allow", fields["decision"])
	assert.Equal(t, true, fields["allowed"])
	assert.Equal(t, "principal-1", fields["matched_principal"])
	assert.Equal(t, "policy-1", fields["matched_policy_id"])
	assert.Equal(t, float64(http.StatusOK), fields["status_code"])
	assert.Contains(t, fields, "decision_duration_ms")
	assert.Contains(t, fields["evaluated_policy_ids"], "policy-1")
}

func testExtAuthzRouter(t *testing.T) *gin.Engine {
	t.Helper()

	return testExtAuthzRouterWithLogger(t, logrus.NewEntry(logrus.New()))
}

func testExtAuthzRouterWithLogger(t *testing.T, logger *logrus.Entry) *gin.Engine {
	t.Helper()

	gin.SetMode(gin.TestMode)
	eng, err := engine.NewEngine(nil, nil, engine.WithHTTPSchemas([]string{writeExtAuthzHTTPSchema(t)}))
	require.NoError(t, err)

	policy := &models.Policy{
		ID:   "policy-1",
		Name: "Policy 1",
		HTTPRules: []*models.HTTPRule{
			{
				SchemaName: "test-http",
				Actions:    []string{"resource-read"},
			},
		},
	}
	resolver := service.NewIdentityResolver(testPrincipalMatcher{}, testGrantStore{}, testPolicyLoader{policy: policy})
	ctrl := NewExtAuthzController(eng, resolver, logger)

	router := gin.New()
	router.Any("/ext_authz/check", ctrl.Check)
	return router
}

func writeExtAuthzHTTPSchema(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "http-schema.json")
	content := `[
		{
			"name": "test-http",
			"routes": [
				{
					"name": "resource-read",
					"methods": ["GET"],
					"path": "/api/v1/resource",
					"match_type": "exact",
					"action": "resource-read"
				}
			]
		}
	]`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

type testPrincipalMatcher struct{}

func (testPrincipalMatcher) MatchPrincipals(_ context.Context, authMaterial interface{}, authType string) ([]string, error) {
	if authType == "oidc" && authMaterial == "Bearer good" {
		return []string{"principal-1"}, nil
	}
	return nil, nil
}

type testPolicyLoader struct {
	policy *models.Policy
}

func (l testPolicyLoader) GetPolicy(_ context.Context, policyID string) (*models.Policy, error) {
	if policyID == l.policy.ID {
		return l.policy, nil
	}
	return nil, service.ErrNoMatch
}

type testGrantStore struct{}

func (testGrantStore) Grant(context.Context, string, string, string) error {
	return nil
}

func (testGrantStore) Revoke(context.Context, string, string) error {
	return nil
}

func (testGrantStore) GrantBatch(context.Context, string, []string, string) error {
	return nil
}

func (testGrantStore) RevokeBatch(context.Context, string, []string) error {
	return nil
}

func (testGrantStore) Has(context.Context, string, string) (bool, error) {
	return false, nil
}

func (testGrantStore) ListForPrincipal(context.Context, string, *resources.QueryParameters) ([]models.PrincipalPolicy, string, error) {
	return []models.PrincipalPolicy{{PrincipalID: "principal-1", PolicyID: "policy-1"}}, "", nil
}

func (testGrantStore) ListForPolicy(context.Context, string) ([]*models.Principal, error) {
	return nil, nil
}

func (testGrantStore) CountForPrincipal(context.Context, string) (int64, error) {
	return 0, nil
}

func (testGrantStore) CountForPolicy(context.Context, string) (int64, error) {
	return 0, nil
}
