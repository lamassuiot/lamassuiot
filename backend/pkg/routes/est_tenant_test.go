package routes

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	tenantcontext "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/tenant-context"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	smock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
)

type estTenantGetterStub map[string]models.Tenant

func (stub estTenantGetterStub) GetActiveTenant(_ context.Context, tenantID string) (*models.Tenant, error) {
	tenant, ok := stub[tenantID]
	if !ok {
		return nil, errors.New("not found")
	}
	return &tenant, nil
}

func TestESTRoutesResolveTenantFromURL(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tenants := estTenantGetterStub{
		"tenant-a":             {ID: "tenant-a", OrganizationID: "org", Status: models.TenantActive},
		models.DefaultTenantID: {ID: models.DefaultTenantID, OrganizationID: "org", Status: models.TenantActive},
	}
	svc := new(smock.MockESTService)
	seen := []string{}
	svc.On("CACerts", mock.Anything, "dms-1").Run(func(args mock.Arguments) {
		tenantContext, err := core.RequireTenantContext(args.Get(0).(context.Context))
		if err != nil {
			t.Errorf("EST service called without tenant context: %s", err)
			return
		}
		seen = append(seen, tenantContext.TenantID)
	}).Return([]*x509.Certificate{}, nil)

	router := gin.New()
	middleware := tenantcontext.NewPublicTenantContextMiddleware(tenants, models.DefaultTenantID, "est")
	logger := logrus.NewEntry(logrus.New())
	NewESTHttpRoutes(logger, router.Group(""), svc, middleware)
	NewESTHttpRoutes(logger, router.Group("/tenants/:tenantId"), svc, middleware)

	for _, test := range []struct {
		path   string
		status int
	}{
		{"/tenants/tenant-a/.well-known/est/dms-1/cacerts", http.StatusOK},
		{"/.well-known/est/dms-1/cacerts", http.StatusOK},
		{"/tenants/unknown/.well-known/est/dms-1/cacerts", http.StatusNotFound},
	} {
		record := httptest.NewRecorder()
		router.ServeHTTP(record, httptest.NewRequest(http.MethodGet, test.path, nil))
		if record.Code != test.status {
			t.Fatalf("%s: expected %d, got %d (%s)", test.path, test.status, record.Code, record.Body.String())
		}
	}
	if len(seen) != 2 || seen[0] != "tenant-a" || seen[1] != models.DefaultTenantID {
		t.Fatalf("EST calls must run in the URL tenant and in the default tenant for legacy routes, got %v", seen)
	}
}
