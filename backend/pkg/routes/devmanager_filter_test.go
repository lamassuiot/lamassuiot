package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	authzcore "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/core"
	authzsdk "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const denyAllDeviceFilter = "SELECT * FROM devicemanager.devices WHERE 1 = 0"

type denyAllFilterEngine struct{ authzcore.AuthzEngine }

func (denyAllFilterEngine) MatchAndGetFilter(context.Context, string, string, string, string, string) (string, []string, error) {
	return denyAllDeviceFilter, []string{"principal"}, nil
}

type statsContextRecorder struct {
	services.DeviceManagerService
	filter any
}

func (s *statsContextRecorder) GetDevicesStats(ctx context.Context, _ services.GetDevicesStatsInput) (*models.DevicesStats, error) {
	s.filter = ctx.Value(authzsdk.AuthzQueryKey)
	return &models.DevicesStats{}, nil
}

// The storage layer applies the authz filter it finds in the context, so a
// handler that drops it returns every device to a principal allowed to see none.
func TestDeviceManagerStatsReceivesAuthzFilter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("lamassu.io/ctx/auth-type", "jwt")
		c.Set("lamassu.io/ctx/auth-credential-string", "test-credential")
		c.Next()
	})
	svc := &statsContextRecorder{}
	registerDeviceManagerRoutes(router.Group("/api/devmanager"), svc, nil, denyAllFilterEngine{}, logrus.NewEntry(logrus.New()))

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/devmanager/v1/stats", nil))

	require.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, denyAllDeviceFilter, svc.filter)
}
