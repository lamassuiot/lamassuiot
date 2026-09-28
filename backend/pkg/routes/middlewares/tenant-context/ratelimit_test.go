package tenantcontext

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
)

func TestTenantRateLimitIsolatesNoisyTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		tenantID := c.GetHeader("X-Test-Tenant")
		c.Request = c.Request.WithContext(core.WithTenantContext(c.Request.Context(), core.TenantContext{
			OrganizationID: "org", TenantID: tenantID, ActorID: "a", ActorType: "SERVICE",
			CorrelationID: "c", Source: "test", TenantStatus: core.TenantActive, Validated: true,
		}))
		c.Next()
	})
	router.Use(NewTenantRateLimitMiddleware(cconfig.HttpServerTenantRateLimit{Enabled: true, RequestsPerSecond: 0.001, Burst: 3}))
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	call := func(tenantID string) *httptest.ResponseRecorder {
		record := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("X-Test-Tenant", tenantID)
		router.ServeHTTP(record, request)
		return record
	}
	for i := 0; i < 3; i++ {
		if code := call("tenant-a").Code; code != http.StatusNoContent {
			t.Fatalf("request %d of tenant A within burst got %d", i, code)
		}
	}
	throttled := call("tenant-a")
	if throttled.Code != http.StatusTooManyRequests || throttled.Header().Get("Retry-After") == "" {
		t.Fatalf("tenant A over its burst must get 429 with Retry-After, got %d", throttled.Code)
	}
	if code := call("tenant-b").Code; code != http.StatusNoContent {
		t.Fatalf("tenant B must not be throttled by tenant A, got %d", code)
	}
}

func TestTenantRateLimitDisabledByDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(NewTenantRateLimitMiddleware(cconfig.HttpServerTenantRateLimit{}))
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	for i := 0; i < 50; i++ {
		record := httptest.NewRecorder()
		router.ServeHTTP(record, httptest.NewRequest(http.MethodGet, "/", nil))
		if record.Code != http.StatusNoContent {
			t.Fatalf("disabled limiter must not reject requests, got %d", record.Code)
		}
	}
}

func TestIdentityRateLimitThrottlesBeforeMembershipLookup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &membershipLookupCounter{}
	identity := func(context.Context) (AuthenticatedIdentity, error) {
		return AuthenticatedIdentity{Issuer: "issuer", Subject: "noisy", ActorType: "HUMAN"}, nil
	}
	router := gin.New()
	router.Use(NewIdentityRateLimitMiddleware(cconfig.HttpServerTenantRateLimit{Enabled: true, RequestsPerSecond: 0.001, Burst: 2}, identity))
	router.Use(NewTenantContextMiddleware(repo, identity))
	router.GET("/tenant", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	throttled := 0
	for i := 0; i < 10; i++ {
		record := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/tenant", nil)
		request.Header.Set(TenantIDHeader, "tenant-1")
		router.ServeHTTP(record, request)
		if record.Code == http.StatusTooManyRequests {
			throttled++
		}
	}
	if throttled != 8 || repo.calls != 2 {
		t.Fatalf("expected 8 throttled requests and only 2 membership lookups, got throttled=%d lookups=%d", throttled, repo.calls)
	}

	record := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/tenant", nil)
	request.Header.Set(TenantIDHeader, "tenant-2")
	router.ServeHTTP(record, request)
	if record.Code == http.StatusTooManyRequests || repo.calls != 3 {
		t.Fatalf("the same identity keeps its own budget in another tenant, got %d lookups=%d", record.Code, repo.calls)
	}
}
