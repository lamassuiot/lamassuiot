package tenantcontext

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenantContextMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("accepts tenant_id from header", func(t *testing.T) {
		router := gin.New()
		router.Use(TenantContextMiddleware())

		var gotGin, gotCtx string
		var okCtx bool
		router.GET("/v1/cas", func(c *gin.Context) {
			gotGin = c.GetString(core.LamassuContextKeyTenantID)
			gotCtx, okCtx = TenantIDFromContext(c.Request.Context())
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/v1/cas", nil)
		req.Header.Set(HeaderTenantID, "tenant-a")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "tenant-a", gotGin)
		assert.True(t, okCtx)
		assert.Equal(t, "tenant-a", gotCtx)
	})

	t.Run("accepts tenant_id from path", func(t *testing.T) {
		router := gin.New()
		grp := router.Group("/v1/tenants/:tenant_id")
		grp.Use(TenantContextMiddleware())

		var gotCtx string
		grp.GET("/cas", func(c *gin.Context) {
			gotCtx, _ = TenantIDFromContext(c.Request.Context())
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/v1/tenants/tenant-b/cas", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "tenant-b", gotCtx)
	})

	t.Run("accepts matching path and header", func(t *testing.T) {
		router := gin.New()
		grp := router.Group("/v1/tenants/:tenant_id")
		grp.Use(TenantContextMiddleware())

		var gotCtx string
		grp.GET("/cas", func(c *gin.Context) {
			gotCtx, _ = TenantIDFromContext(c.Request.Context())
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/v1/tenants/tenant-c/cas", nil)
		req.Header.Set(HeaderTenantID, "tenant-c")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "tenant-c", gotCtx)
	})

	t.Run("rejects conflicting path and header with 400", func(t *testing.T) {
		router := gin.New()
		grp := router.Group("/v1/tenants/:tenant_id")
		grp.Use(TenantContextMiddleware())

		called := false
		grp.GET("/cas", func(c *gin.Context) {
			called = true
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/v1/tenants/tenant-a/cas", nil)
		req.Header.Set(HeaderTenantID, "tenant-b")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.False(t, called)
	})

	t.Run("rejects missing tenant_id with 400", func(t *testing.T) {
		router := gin.New()
		router.Use(TenantContextMiddleware())

		called := false
		router.GET("/v1/cas", func(c *gin.Context) {
			called = true
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/v1/cas", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.False(t, called)
	})

	t.Run("rejects invalid tenant_id format with 400", func(t *testing.T) {
		for _, bad := range []string{"tenant with spaces", "tenant\ninjection", strings.Repeat("a", maxTenantIDLength+1)} {
			router := gin.New()
			router.Use(TenantContextMiddleware())
			router.GET("/v1/cas", func(c *gin.Context) { c.Status(http.StatusOK) })

			req := httptest.NewRequest(http.MethodGet, "/v1/cas", nil)
			req.Header.Set(HeaderTenantID, bad)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusBadRequest, w.Code)
		}
	})
}
