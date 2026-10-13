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
	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/api/dto"
	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/engine"
	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/service"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckHTTP_AllowsKnownPrincipalWithSubjectAttribute(t *testing.T) {
	router := testHTTPAuthzCheckRouter(t)

	body := map[string]interface{}{
		"principal_id": "principal-1",
		"subject_attributes": map[string]string{
			"client_id": "hub-1",
		},
		"request": map[string]string{
			"method":    "GET",
			"path":      "/api/wfx/sbi/v1/jobs",
			"raw_query": "clientId=hub-1",
		},
	}

	rec := performHTTPCheckRequest(t, router, "/authz/http/check", body)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp dto.HTTPAuthzCheckResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.True(t, resp.Allowed)
	assert.Equal(t, "principal-1", resp.MatchedPrincipalID)
	assert.Equal(t, []string{"principal-1"}, resp.MatchedPrincipals)
	assert.Equal(t, "policy-1", resp.MatchedPolicyID)
	assert.Equal(t, "sbi-job-list", resp.MatchedAction)
	assert.Equal(t, "hub-1", resp.SubjectAttributes["client_id"])
	assert.Equal(t, "http_rule grants access to this route", resp.Reason)
}

func TestCheckHTTP_DeniesKnownPrincipalWhenConstraintAttributeMissing(t *testing.T) {
	router := testHTTPAuthzCheckRouter(t)

	body := map[string]interface{}{
		"principal_id": "principal-1",
		"request": map[string]string{
			"method":    "GET",
			"path":      "/api/wfx/sbi/v1/jobs",
			"raw_query": "clientId=hub-1",
		},
	}

	rec := performHTTPCheckRequest(t, router, "/authz/http/check", body)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp dto.HTTPAuthzCheckResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.False(t, resp.Allowed)
	assert.Equal(t, "no http_rule grants access to this route", resp.Reason)
	assert.Empty(t, resp.MatchedPolicyID)
	assert.Empty(t, resp.MatchedAction)
}

func TestMatchAndCheckHTTP_AllowsCredentialResolvedSubjectAttribute(t *testing.T) {
	router := testHTTPAuthzCheckRouter(t)

	body := map[string]interface{}{
		"auth_type":     "oidc",
		"auth_material": "Bearer good",
		"request": map[string]string{
			"method":    "GET",
			"path":      "/api/wfx/sbi/v1/jobs",
			"raw_query": "clientId=hub-1",
		},
	}

	rec := performHTTPCheckRequest(t, router, "/authz/match/http/check", body)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp dto.HTTPAuthzCheckResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.True(t, resp.Allowed)
	assert.Equal(t, "principal-1", resp.MatchedPrincipalID)
	assert.Equal(t, []string{"principal-1"}, resp.MatchedPrincipals)
	assert.Equal(t, "policy-1", resp.MatchedPolicyID)
	assert.Equal(t, "sbi-job-list", resp.MatchedAction)
	assert.Equal(t, "hub-1", resp.SubjectAttributes["client_id"])
	assert.Equal(t, "http_rule grants access to this route", resp.Reason)
}

func performHTTPCheckRequest(t *testing.T, router *gin.Engine, path string, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()

	raw, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func testHTTPAuthzCheckRouter(t *testing.T) *gin.Engine {
	t.Helper()

	gin.SetMode(gin.TestMode)
	eng, err := engine.NewEngine(nil, nil, engine.WithHTTPSchemas([]string{writeHTTPAuthzCheckSchema(t)}))
	require.NoError(t, err)

	policy := &models.Policy{
		ID:   "policy-1",
		Name: "Policy 1",
		HTTPRules: []*models.HTTPRule{
			{
				SchemaName: "test-http",
				Actions:    []string{"sbi-job-list"},
			},
		},
	}
	resolver := service.NewIdentityResolver(testPrincipalMatcher{}, testGrantStore{}, testPolicyLoader{policy: policy})
	ctrl := NewAuthzController(eng, resolver, logrus.NewEntry(logrus.New()))

	router := gin.New()
	router.POST("/authz/http/check", ctrl.CheckHTTP)
	router.POST("/authz/match/http/check", ctrl.MatchAndCheckHTTP)
	return router
}

func writeHTTPAuthzCheckSchema(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "http-schema.json")
	content := `[
		{
			"name": "test-http",
			"routes": [
				{
					"name": "sbi-job-list",
					"methods": ["GET"],
					"path": "/api/wfx/sbi/v1/jobs",
					"match_type": "exact",
					"action": "sbi-job-list",
					"constraints": [
						{
							"request": { "source": "query", "name": "clientId" },
							"equals_subject_attribute": "client_id"
						}
					]
				}
			]
		}
	]`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func (testPrincipalMatcher) MatchSubjects(_ context.Context, authMaterial interface{}, authType string) ([]engine.ResolvedSubject, error) {
	if authType == "oidc" && authMaterial == "Bearer good" {
		return []engine.ResolvedSubject{
			{
				PrincipalID: "principal-1",
				Attributes:  map[string]string{"client_id": "hub-1"},
			},
		}, nil
	}
	return nil, nil
}
