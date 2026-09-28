package assemblers

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	tenantcontext "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/tenant-context"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/storage/builder"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/sirupsen/logrus"
)

func newTenantRouteOptions(logger *logrus.Entry, storageConfig cconfig.PluggableStorageEngine, server cconfig.HttpServer) (routes.TenantRouteOptions, error) {
	engine, err := builder.BuildStorageEngine(logger, storageConfig)
	if err != nil {
		return routes.TenantRouteOptions{}, fmt.Errorf("could not create tenant membership storage: %w", err)
	}
	memberships, err := engine.GetControlPlaneMembershipStorage()
	if err != nil {
		return routes.TenantRouteOptions{}, fmt.Errorf("could not get tenant membership storage: %w", err)
	}
	jwtValidator, err := identityextractors.NewJWTValidator(server.Authentication.JWT, nil)
	if err != nil {
		return routes.TenantRouteOptions{}, fmt.Errorf("could not configure JWT authentication: %w", err)
	}
	return routes.TenantRouteOptions{
		Memberships:      memberships,
		IdentityProvider: tenantcontext.HTTPIdentityProvider,
		Authorization:    tenantcontext.NewPermissionAuthorizationEngine(),
		JWTValidator:     jwtValidator,
		Versioning:       server.Versioning,
		RateLimit:        server.TenantRateLimit,
	}, nil
}

// resolveTenantRouteOptions returns the injected options when the caller
// provides them (in-process test servers) and the configured ones otherwise.
func resolveTenantRouteOptions(logger *logrus.Entry, storageConfig cconfig.PluggableStorageEngine, server cconfig.HttpServer, overrides []routes.TenantRouteOptions) (routes.TenantRouteOptions, error) {
	if len(overrides) > 0 {
		return overrides[0], nil
	}
	return newTenantRouteOptions(logger, storageConfig, server)
}
