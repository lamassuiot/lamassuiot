package identityextractors

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v4"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

// mixedCaseIssuer tiene mayúsculas y puntos, como un realm de Keycloak
// ("Lamassu"): Keycloak distingue mayúsculas en el nombre del realm.
const mixedCaseIssuer = "https://Keycloak.Example.com/realms/Lamassu"

type jwtServiceConfig struct {
	Server cconfig.HttpServer `mapstructure:"server"`
}

// newJWKSTestServer sirve por HTTPS un JWKS con la clave pública de key.
func newJWKSTestServer(t *testing.T, key *rsa.PrivateKey) *httptest.Server {
	t.Helper()
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &key.PublicKey,
		KeyID:     "key-1",
		Algorithm: jwt.SigningMethodRS256.Alg(),
		Use:       "sig",
	}}})
	require.NoError(t, err)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(jwks)
	}))
	t.Cleanup(server.Close)
	return server
}

// loadJWTConfig escribe jwtYAML (el bloque server.authentication.jwt) en un
// fichero temporal y lo carga con el mismo cargador que los servicios.
func loadJWTConfig(t *testing.T, jwtYAML string) cconfig.HttpServerJWTAuthentication {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	content := "server:\n  authentication:\n    jwt:\n      enabled: true\n      audience: \"lamassu\"\n      allowed_algorithms: [\"RS256\"]\n      jwks_cache_ttl: \"5m\"\n" + jwtYAML
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	t.Setenv("LAMASSU_CONFIG_FILE", path)
	conf, err := cconfig.LoadConfig[jwtServiceConfig](nil)
	require.NoError(t, err)
	return conf.Server.Authentication.JWT
}

func signTestToken(t *testing.T, key *rsa.PrivateKey, issuer string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": issuer,
		"aud": "lamassu",
		"sub": "actor-1",
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	token.Header["kid"] = "key-1"
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

// TestJWTValidatorIssuerJWKSListKeepsIssuerCase carga issuer_jwks con un
// issuer con mayúsculas y puntos y comprueba que se acepta un token con ese
// iss exacto y se rechaza con el iss en minúsculas (005 T2).
func TestJWTValidatorIssuerJWKSListKeepsIssuerCase(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	server := newJWKSTestServer(t, key)

	jwtConfig := loadJWTConfig(t, fmt.Sprintf("      issuer_jwks:\n        - issuer: %q\n          jwks_url: %q\n", mixedCaseIssuer, server.URL))
	logger, hook := logtest.NewNullLogger()
	validator, err := NewJWTValidator(logrus.NewEntry(logger), jwtConfig, server.Client())
	require.NoError(t, err)
	require.Contains(t, validator.AllowedIssuers, mixedCaseIssuer)
	for _, entry := range hook.AllEntries() {
		require.NotEqual(t, logrus.WarnLevel, entry.Level, "unexpected warning: %s", entry.Message)
	}

	_, err = validator.Validate(signTestToken(t, key, mixedCaseIssuer))
	require.NoError(t, err)

	_, err = validator.Validate(signTestToken(t, key, strings.ToLower(mixedCaseIssuer)))
	require.ErrorContains(t, err, "issuer")
}

// TestJWTValidatorAcceptsDeprecatedIssuerJWKSURLs comprueba que el formato
// antiguo issuer_jwks_urls se sigue aceptando durante la transición y que se
// avisa en el log de que está obsoleto (005 T2).
func TestJWTValidatorAcceptsDeprecatedIssuerJWKSURLs(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	server := newJWKSTestServer(t, key)
	issuer := "https://keycloak.example.com/realms/lamassu"

	jwtConfig := loadJWTConfig(t, fmt.Sprintf("      issuer_jwks_urls:\n        %q: %q\n", issuer, server.URL))
	logger, hook := logtest.NewNullLogger()
	validator, err := NewJWTValidator(logrus.NewEntry(logger), jwtConfig, server.Client())
	require.NoError(t, err)

	_, err = validator.Validate(signTestToken(t, key, issuer))
	require.NoError(t, err)

	warned := false
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "issuer_jwks_urls") && strings.Contains(entry.Message, "issuer_jwks") {
			warned = true
		}
	}
	require.True(t, warned, "expected a deprecation warning for issuer_jwks_urls")
}

// TestJWTValidatorRejectsBothIssuerFormats comprueba que definir a la vez
// issuer_jwks e issuer_jwks_urls es un error de configuración claro (005 T2).
func TestJWTValidatorRejectsBothIssuerFormats(t *testing.T) {
	issuer := "https://keycloak.example.com/realms/lamassu"
	jwtConfig := loadJWTConfig(t, fmt.Sprintf("      issuer_jwks:\n        - issuer: %q\n          jwks_url: %q\n      issuer_jwks_urls:\n        %q: %q\n",
		issuer, issuer+"/certs", issuer, issuer+"/certs"))

	_, err := NewJWTValidator(logrus.NewEntry(logrus.New()), jwtConfig, nil)
	require.ErrorContains(t, err, "issuer_jwks")
	require.ErrorContains(t, err, "issuer_jwks_urls")
}
