package config

import (
	"testing"

	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mixedCaseIssuer es el issuer con mayúsculas y puntos que usan los values de
// testdata/helm (un realm de Keycloak distingue mayúsculas).
const mixedCaseIssuer = "https://Keycloak.Example.com/realms/Lamassu"

// serviceConfig es la parte común de la configuración de los servicios.
type serviceConfig struct {
	Server  cconfig.HttpServer
	Storage cconfig.PluggableStorageEngine
}

func loadHelmConfig[E any](t *testing.T, service string, common func(*E) serviceConfig) {
	t.Helper()
	t.Setenv("LAMASSU_CONFIG_FILE", "testdata/helm/"+service+".yml")

	conf, err := cconfig.LoadConfig[E](nil)
	require.NoError(t, err)
	require.NotNil(t, conf)

	c := common(conf)
	assert.NotZero(t, c.Server.Port, "server.port")
	assert.Equal(t, "0.0.0.0", c.Server.ListenAddress, "server.listen_address")
	assert.Equal(t, cconfig.Postgres, c.Storage.Provider, "storage.provider")
	assert.True(t, c.Server.Authentication.JWT.Enabled, "server.authentication.jwt.enabled")
	assert.Equal(t, "lamassu", c.Server.Authentication.JWT.Audience)
	assert.Equal(t, []cconfig.HttpServerJWTIssuer{{
		Issuer:  mixedCaseIssuer,
		JWKSURL: mixedCaseIssuer + "/protocol/openid-connect/certs",
	}}, c.Server.Authentication.JWT.IssuerJWKS)
	assert.Empty(t, c.Server.Authentication.JWT.IssuerJWKSURLs)
}

// TestLoadHelmServiceConfigs carga la configuración que el chart genera para
// cada servicio, con un issuer JWT con mayúsculas y puntos en la lista
// issuer_jwks (005 T2). Los ficheros de testdata/helm salen de `helm template`
// de lamassu-helm con auth.backendJwt.enabled=true, auth.backendJwt.issuerJwks
// y services.tenantManager.enabled=true.
func TestLoadHelmServiceConfigs(t *testing.T) {
	t.Run("alerts", func(t *testing.T) {
		loadHelmConfig(t, "alerts", func(c *AlertsConfig) serviceConfig { return serviceConfig{c.Server, c.Storage} })
	})
	t.Run("ca", func(t *testing.T) {
		loadHelmConfig(t, "ca", func(c *CAConfig) serviceConfig { return serviceConfig{c.Server, c.Storage} })
	})
	t.Run("device-manager", func(t *testing.T) {
		loadHelmConfig(t, "device-manager", func(c *DeviceManagerConfig) serviceConfig { return serviceConfig{c.Server, c.Storage} })
	})
	t.Run("dms-manager", func(t *testing.T) {
		loadHelmConfig(t, "dms-manager", func(c *DMSconfig) serviceConfig { return serviceConfig{c.Server, c.Storage} })
	})
	t.Run("kms", func(t *testing.T) {
		loadHelmConfig(t, "kms", func(c *KMSConfig) serviceConfig { return serviceConfig{c.Server, c.Storage} })
	})
	t.Run("tenant-manager", func(t *testing.T) {
		loadHelmConfig(t, "tenant-manager", func(c *TenantManagerConfig) serviceConfig { return serviceConfig{c.Server, c.Storage} })
	})
	t.Run("va", func(t *testing.T) {
		loadHelmConfig(t, "va", func(c *VAconfig) serviceConfig { return serviceConfig{c.Server, c.Storage} })
	})
}
