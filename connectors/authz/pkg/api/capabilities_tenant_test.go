package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/service"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type capStubMatcher struct {
	principals []string
}

func (m *capStubMatcher) MatchPrincipals(_ context.Context, _ any, _ string) ([]string, error) {
	return m.principals, nil
}

type capStubTenantChecker struct {
	allowed map[string]map[string]bool
}

func (c *capStubTenantChecker) IsPrincipalInTenant(_ context.Context, tenantID, principalID string) (bool, error) {
	return c.allowed[tenantID][principalID], nil
}

func TestCapabilitiesControllerEnforcesTenantID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	resolver := service.NewIdentityResolver(&capStubMatcher{principals: []string{"p-tenant-a"}}, nil, nil)
	resolver.SetTenantPrincipalChecker(&capStubTenantChecker{
		allowed: map[string]map[string]bool{
			"tenant-a": {"p-tenant-a": true},
		},
	})

	ctrl := NewCapabilitiesController(nil, nil, nil, resolver, logrus.NewEntry(logrus.New()))
	router := gin.New()
	router.POST("/capabilities/global", ctrl.GetGlobalCapabilities)
	router.POST("/match/capabilities/global", ctrl.MatchAndGetGlobalCapabilities)

	t.Run("GetGlobalCapabilities rejects principal outside requested tenant with 403", func(t *testing.T) {
		body := bytes.NewBufferString(`{"principal_id":"p-tenant-a","tenant_id":"tenant-b"}`)
		req := httptest.NewRequest(http.MethodPost, "/capabilities/global", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("MatchAndGetGlobalCapabilities rejects matched principal outside requested tenant with 403", func(t *testing.T) {
		body := bytes.NewBufferString(`{"auth_type":"oidc","auth_material":"jwt-token","tenant_id":"tenant-b"}`)
		req := httptest.NewRequest(http.MethodPost, "/match/capabilities/global", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}
