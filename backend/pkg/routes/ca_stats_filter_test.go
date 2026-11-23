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

// perEntityFilterEngine returns a different list filter per entity, as the authz service
// does for a principal with different CA and certificate permissions.
type perEntityFilterEngine struct{ authzcore.AuthzEngine }

var caStatsFilters = map[string]string{
	"ca_certificate": "SELECT * FROM ca.ca_certificates WHERE 1 = 1",
	"certificate":    "SELECT * FROM ca.certificates_view AS certificates WHERE 1 = 0",
}

func (perEntityFilterEngine) MatchAndGetFilter(_ context.Context, _, _, _, _, entityType string) (string, []string, error) {
	return caStatsFilters[entityType], []string{"principal"}, nil
}

type caStatsFilterRecorder struct {
	services.CAService
	caStatsFilter, certStatsFilter any
}

func (s *caStatsFilterRecorder) GetStats(ctx context.Context, _ services.GetStatsInput) (*models.CAStats, error) {
	s.caStatsFilter = ctx.Value(authzsdk.AuthzQueryKey)
	return &models.CAStats{}, nil
}

func (s *caStatsFilterRecorder) GetCertificatesStats(ctx context.Context, _ services.GetCertificatesStatsInput) (*models.CertificatesStats, error) {
	s.certStatsFilter = ctx.Value(authzsdk.AuthzQueryKey)
	return &models.CertificatesStats{}, nil
}

// A principal who may read every CA but no certificate must get certificate counts under
// the certificate filter. With the CA filter (the bug the split fixes) the storage layer
// skips it for the certificates table and counts every certificate.
func TestCAStatisticsRoutesUseTheFilterOfTheirOwnEntity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("lamassu.io/ctx/auth-type", "jwt")
		c.Set("lamassu.io/ctx/auth-credential-string", "test-credential")
		c.Next()
	})
	svc := &caStatsFilterRecorder{}
	registerCARoutes(router.Group("/api/ca"), svc, perEntityFilterEngine{}, logrus.NewEntry(logrus.New()))

	for _, path := range []string{"/api/ca/v1/certificates/stats", "/api/ca/v1/stats"} {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			// No X-Principal-ID: admin-mode, so the list guard runs.
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			require.Equal(t, http.StatusOK, response.Code)
		})
	}
	assert.Equal(t, caStatsFilters["certificate"], svc.certStatsFilter)
	assert.Equal(t, caStatsFilters["ca_certificate"], svc.caStatsFilter)
}
