package tenantcontext

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type activeTenantGetterStub map[string]models.Tenant

func (stub activeTenantGetterStub) GetActiveTenant(_ context.Context, tenantID string) (*models.Tenant, error) {
	tenant, ok := stub[tenantID]
	if !ok || tenant.Status != models.TenantActive {
		return nil, errors.New("not found")
	}
	return &tenant, nil
}

func TestPublicTenantContextMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tenants := activeTenantGetterStub{
		"tenant-a":       {ID: "tenant-a", OrganizationID: "org-a", Status: models.TenantActive},
		"default-tenant": {ID: "default-tenant", OrganizationID: "org-d", Status: models.TenantActive},
		"suspended":      {ID: "suspended", OrganizationID: "org-s", Status: models.TenantSuspended},
	}
	router := gin.New()
	handler := func(c *gin.Context) {
		tenantContext, err := core.RequireTenantContext(c.Request.Context())
		if err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.String(http.StatusOK, tenantContext.OrganizationID+"/"+tenantContext.TenantID+"/"+tenantContext.ActorType)
	}
	middleware := NewPublicTenantContextMiddleware(tenants, "default-tenant", "va")
	router.GET("/crl/:ca-ski", middleware, handler)
	router.GET("/tenants/:tenantId/crl/:ca-ski", middleware, handler)

	for _, test := range []struct {
		path   string
		status int
		body   string
	}{
		{"/tenants/tenant-a/crl/abcd", http.StatusOK, "org-a/tenant-a/PUBLIC"},
		{"/crl/abcd", http.StatusOK, "org-d/default-tenant/PUBLIC"},
		{"/tenants/suspended/crl/abcd", http.StatusNotFound, ""},
		{"/tenants/unknown/crl/abcd", http.StatusNotFound, ""},
	} {
		record := httptest.NewRecorder()
		router.ServeHTTP(record, httptest.NewRequest(http.MethodGet, test.path, nil))
		if record.Code != test.status || (test.body != "" && record.Body.String() != test.body) {
			t.Fatalf("%s: got %d %q, want %d %q", test.path, record.Code, record.Body.String(), test.status, test.body)
		}
	}

	unconfigured := gin.New()
	unconfigured.GET("/crl/:ca-ski", NewPublicTenantContextMiddleware(nil, "default-tenant", "va"), handler)
	record := httptest.NewRecorder()
	unconfigured.ServeHTTP(record, httptest.NewRequest(http.MethodGet, "/crl/abcd", nil))
	if record.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 without a tenant resolver, got %d", record.Code)
	}
}
