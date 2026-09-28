package pkg

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	tenantcontext "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/tenant-context"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/storage/builder"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
)

const jwksRequestTimeout = 5 * time.Second

// tenantRouteOptionsBuilder construye las TenantRouteOptions de cada servicio
// igual que newTenantRouteOptions del backend (memberships de controlplane,
// identidad HTTP, RBAC), salvo el cliente del JWKS: el monolito le pasa uno
// que confía en la CA del emisor local y en las de -issuer-ca-file, sin tocar
// SSL_CERT_DIR del proceso (design.md, «Confianza en el JWKS»).
type tenantRouteOptionsBuilder struct {
	memberships storage.ControlPlaneMembershipRepo
	jwksClient  *http.Client
}

func newTenantRouteOptionsBuilder(conf MonolithicConfig) (*tenantRouteOptionsBuilder, error) {
	jwksClient, err := newJWKSClient(conf.Multitenant.JWKSTrustedCAFiles)
	if err != nil {
		return nil, err
	}
	logger := chelpers.SetupLogger(conf.Storage.LogLevel, "Monolithic", "Tenant memberships")
	engine, err := builder.BuildStorageEngine(logger, conf.Storage)
	if err != nil {
		return nil, fmt.Errorf("could not create tenant membership storage: %w", err)
	}
	memberships, err := engine.GetControlPlaneMembershipStorage()
	if err != nil {
		return nil, fmt.Errorf("could not get tenant membership storage: %w", err)
	}
	return &tenantRouteOptionsBuilder{memberships: memberships, jwksClient: jwksClient}, nil
}

func (b *tenantRouteOptionsBuilder) build(serviceName string, server cconfig.HttpServer) (routes.TenantRouteOptions, error) {
	logger := chelpers.SetupLogger(server.LogLevel, serviceName, "JWT")
	validator, err := identityextractors.NewJWTValidator(logger, server.Authentication.JWT, b.jwksClient)
	if err != nil {
		return routes.TenantRouteOptions{}, fmt.Errorf("could not configure JWT authentication for %s: %w", serviceName, err)
	}
	if validator == nil {
		// devprofile nunca desactiva JWT; si llegara aquí, se falla cerrado.
		return routes.TenantRouteOptions{}, fmt.Errorf("JWT authentication is disabled for %s: the multitenant profile requires it", serviceName)
	}
	return routes.TenantRouteOptions{
		Memberships:      b.memberships,
		IdentityProvider: tenantcontext.HTTPIdentityProvider,
		Authorization:    tenantcontext.NewPermissionAuthorizationEngine(),
		JWTValidator:     validator,
		Versioning:       server.Versioning,
		RateLimit:        server.TenantRateLimit,
	}, nil
}

// newJWKSClient devuelve un cliente HTTPS que confía en las CA del sistema y
// en las de caFiles.
func newJWKSClient(caFiles []string) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, file := range caFiles {
		pemBytes, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("could not read JWKS trusted CA %s: %w", file, err)
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("JWKS trusted CA %s contains no PEM certificates", file)
		}
	}
	return &http.Client{
		Timeout: jwksRequestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}, nil
}
