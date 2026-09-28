package routes

import (
	"context"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	tenantcontext "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/tenant-context"
	"github.com/lamassuiot/lamassuiot/core/v3"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

func TestV1CompatibilityMiddlewareAppliesDefaultTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(NewV1CompatibilityMiddleware(cconfig.HttpServerVersioning{
		V1DefaultTenantID: "tenant-default",
		V1SunsetAt:        time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
	}, func() time.Time { return time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC) }))
	router.GET("/v1/cas", func(c *gin.Context) {
		if c.GetHeader(tenantcontext.TenantIDHeader) != "tenant-default" {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusNoContent)
	})

	record := httptest.NewRecorder()
	router.ServeHTTP(record, httptest.NewRequest(http.MethodGet, "/v1/cas", nil))
	if record.Code != http.StatusNoContent || record.Header().Get("Deprecation") != "true" {
		t.Fatalf("expected active v1 compatibility, got status=%d headers=%v", record.Code, record.Header())
	}
}

func TestV1CompatibilityMiddlewareRejectsInvalidConfigurationAndSunset(t *testing.T) {
	for name, config := range map[string]cconfig.HttpServerVersioning{
		"missing configuration": {V1SunsetAt: time.Now().Add(time.Hour)},
		"sunset":                {V1DefaultTenantID: "tenant-default", V1SunsetAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)},
	} {
		t.Run(name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.Use(NewV1CompatibilityMiddleware(config, func() time.Time { return time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC) }))
			router.GET("/v1/cas", func(c *gin.Context) { c.Status(http.StatusNoContent) })

			record := httptest.NewRecorder()
			router.ServeHTTP(record, httptest.NewRequest(http.MethodGet, "/v1/cas", nil))
			expected := http.StatusServiceUnavailable
			if name == "sunset" {
				expected = http.StatusGone
			}
			if record.Code != expected {
				t.Fatalf("expected %d, got %d", expected, record.Code)
			}
		})
	}
}

func TestV1CompatibilityMiddlewareRejectsTenantOverride(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(NewV1CompatibilityMiddleware(cconfig.HttpServerVersioning{
		V1DefaultTenantID: "tenant-default",
		V1SunsetAt:        time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
	}, func() time.Time { return time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC) }))
	router.GET("/v1/cas", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	record := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/cas", nil)
	request.Header.Set(tenantcontext.TenantIDHeader, "tenant-other")
	router.ServeHTTP(record, request)
	if record.Code != http.StatusBadRequest {
		t.Fatalf("expected tenant override to be rejected, got %d", record.Code)
	}
}

func TestVersionedGroupsPublishTenantAwareV2Path(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	_, v2 := VersionedGroups(router.Group("/"))
	v2.GET("/cas", func(c *gin.Context) {
		if c.Param("tenantId") != "tenant-a" {
			t.Fatal("expected tenantId route parameter")
		}
		c.Status(http.StatusNoContent)
	})

	record := httptest.NewRecorder()
	router.ServeHTTP(record, httptest.NewRequest(http.MethodGet, "/api/v2/tenants/tenant-a/cas", nil))
	if record.Code != http.StatusNoContent {
		t.Fatalf("expected v2 route to be published, got %d", record.Code)
	}
}

func TestPermissionGroupEnforcesTenantMembershipAndPermission(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	identityProvider := func(context.Context) (tenantcontext.AuthenticatedIdentity, error) {
		return tenantcontext.AuthenticatedIdentity{
			Issuer:      "issuer",
			Subject:     "actor",
			ActorType:   "HUMAN",
			Permissions: []string{"certificate.read"},
		}, nil
	}
	authorization := tenantcontext.NewPermissionAuthorizationEngine()
	_, v2 := TenantAwareGroups(router.Group("/"), TenantRouteOptions{
		Memberships:      permissionTestMembershipRepo{},
		IdentityProvider: identityProvider,
		Authorization:    authorization,
	})
	PermissionGroup(v2, "certificate.read", authorization).GET("/certificates", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	for _, testCase := range []struct {
		name string
		path string
		want int
	}{
		{name: "authorized tenant", path: "/api/v2/tenants/tenant-a/certificates", want: http.StatusNoContent},
		{name: "foreign tenant", path: "/api/v2/tenants/tenant-b/certificates", want: http.StatusForbidden},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			record := httptest.NewRecorder()
			router.ServeHTTP(record, httptest.NewRequest(http.MethodGet, testCase.path, nil))
			if record.Code != testCase.want {
				t.Fatalf("expected status %d, got %d", testCase.want, record.Code)
			}
		})
	}
}

func TestTenantAwareV1AppliesDefaultTenantAndPermission(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	authorization := tenantcontext.NewPermissionAuthorizationEngine()
	v1, _ := TenantAwareGroups(router.Group("/"), TenantRouteOptions{
		Memberships: permissionTestMembershipRepo{},
		IdentityProvider: func(context.Context) (tenantcontext.AuthenticatedIdentity, error) {
			return tenantcontext.AuthenticatedIdentity{
				Issuer:      "issuer",
				Subject:     "actor",
				ActorType:   "HUMAN",
				Permissions: []string{"certificate.read"},
			}, nil
		},
		Authorization: authorization,
		Versioning: cconfig.HttpServerVersioning{
			V1DefaultTenantID: "tenant-a",
			V1SunsetAt:        time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	})
	PermissionGroup(v1, "certificate.read", authorization).GET("/certificates", func(c *gin.Context) {
		tenantContext, err := core.RequireTenantContext(c.Request.Context())
		if err != nil || tenantContext.TenantID != "tenant-a" {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusNoContent)
	})

	record := httptest.NewRecorder()
	router.ServeHTTP(record, httptest.NewRequest(http.MethodGet, "/v1/certificates", nil))
	if record.Code != http.StatusNoContent || record.Header().Get("Deprecation") != "true" {
		t.Fatalf("expected compatible v1 request with tenant context, got status=%d headers=%v", record.Code, record.Header())
	}
}

func TestTenantAwareRoutesFailClosedWhenNotConfigured(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	NewCAHTTPLayer(router.Group("/"), nil)

	for path, wantStatus := range map[string]int{
		"/api/v2/tenants/tenant-a/cas": http.StatusInternalServerError,
		"/v1/cas":                      http.StatusServiceUnavailable,
	} {
		record := httptest.NewRecorder()
		router.ServeHTTP(record, httptest.NewRequest(http.MethodGet, path, nil))
		if record.Code != wantStatus {
			t.Errorf("%s: expected fail-closed status %d, got %d", path, wantStatus, record.Code)
		}
	}
}

func TestTenantAwareDMSAndKMSRoutesRejectForeignTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(tenantcontext.NewTenantContextMiddleware(permissionTestMembershipRepo{role: models.RolePKIAdmin}, func(context.Context) (tenantcontext.AuthenticatedIdentity, error) {
		return tenantcontext.AuthenticatedIdentity{
			Issuer:      "issuer",
			Subject:     "actor",
			ActorType:   "SERVICE",
			Permissions: []string{"dms.read", "key.read"},
		}, nil
	}))

	v2 := router.Group("/api/v2/tenants/:tenantId")
	PermissionGroup(v2, "dms.read", tenantcontext.NewPermissionAuthorizationEngine()).GET("/dms", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	PermissionGroup(v2, "key.read", tenantcontext.NewPermissionAuthorizationEngine()).GET("/keys", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	for _, path := range []string{"/api/v2/tenants/tenant-a/dms", "/api/v2/tenants/tenant-a/keys"} {
		t.Run(path, func(t *testing.T) {
			record := httptest.NewRecorder()
			router.ServeHTTP(record, httptest.NewRequest(http.MethodGet, path, nil))
			if record.Code != http.StatusNoContent {
				t.Fatalf("expected authorized tenant route to succeed, got %d", record.Code)
			}
		})
	}

	for _, path := range []string{"/api/v2/tenants/tenant-b/dms", "/api/v2/tenants/tenant-b/keys"} {
		t.Run(path, func(t *testing.T) {
			record := httptest.NewRecorder()
			router.ServeHTTP(record, httptest.NewRequest(http.MethodGet, path, nil))
			if record.Code != http.StatusForbidden {
				t.Fatalf("expected foreign tenant route to be rejected, got %d", record.Code)
			}
		})
	}
}

type permissionTestMembershipRepo struct {
	role models.TenantRole
}

func (repo permissionTestMembershipRepo) FindActiveMembership(_ context.Context, issuer string, subject string, tenantID string) (*models.Membership, *models.Tenant, error) {
	if issuer != "issuer" || subject != "actor" || tenantID != "tenant-a" {
		return nil, nil, storage.ErrActiveMembershipNotFound
	}
	role := repo.role
	if role == "" {
		role = models.RoleViewer
	}
	return &models.Membership{
		OrganizationID:  "organization",
		TenantID:        tenantID,
		IdentityIssuer:  issuer,
		IdentitySubject: subject,
		Role:            role,
		Status:          models.MembershipActive,
	}, &models.Tenant{
		ID:             tenantID,
		OrganizationID: "organization",
		Status:         models.TenantActive,
	}, nil
}
