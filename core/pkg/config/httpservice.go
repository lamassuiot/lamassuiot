package config

import (
	"errors"
	"fmt"
	"time"
)

type HTTPConnection struct {
	Protocol        HTTPProtocol `mapstructure:"protocol"`
	BasePath        string       `mapstructure:"base_path"`
	BasicConnection `mapstructure:",squash"`
}

type HTTPProtocol string

const (
	HTTPS HTTPProtocol = "https"
	HTTP  HTTPProtocol = "http"
)

// HttpServer is the configuration for the HTTP server

type HttpServer struct {
	LogLevel           LogLevel                   `mapstructure:"log_level"`
	HealthCheckLogging bool                       `mapstructure:"health_check"`
	ListenAddress      string                     `mapstructure:"listen_address"`
	Port               int                        `mapstructure:"port"`
	Protocol           HTTPProtocol               `mapstructure:"protocol"`
	CertFile           string                     `mapstructure:"cert_file"`
	KeyFile            string                     `mapstructure:"key_file"`
	Authentication     HttpServerAuthentication   `mapstructure:"authentication"`
	Versioning         HttpServerVersioning       `mapstructure:"versioning"`
	CORSAllowedOrigins []string                   `mapstructure:"cors_allowed_origins"`
	TenantRateLimit    HttpServerTenantRateLimit  `mapstructure:"tenant_rate_limit"`
	InternalListener   HttpServerInternalListener `mapstructure:"internal_listener"`
}

// HttpServerInternalListener is a second HTTPS listener for service-to-service
// calls. It requires a client certificate issued by ClientCAFile (the internal
// platform CA); requests accepted there act as the internal service identity
// on the tenant already validated by the original request.
type HttpServerInternalListener struct {
	Enabled      bool   `mapstructure:"enabled"`
	Port         int    `mapstructure:"port"`
	CertFile     string `mapstructure:"cert_file"`
	KeyFile      string `mapstructure:"key_file"`
	ClientCAFile string `mapstructure:"client_ca_file"`
}

// HttpServerTenantRateLimit caps the requests each tenant can make to the
// tenant-scoped routes of one service instance (token bucket per tenant).
type HttpServerTenantRateLimit struct {
	Enabled           bool    `mapstructure:"enabled"`
	RequestsPerSecond float64 `mapstructure:"requests_per_second"`
	Burst             int     `mapstructure:"burst"`
}

type HttpServerAuthentication struct {
	MutualTLS HttpServerMutualTLSAuthentication `mapstructure:"mutual_tls"`
	JWT       HttpServerJWTAuthentication       `mapstructure:"jwt"`
}

type HttpServerJWTAuthentication struct {
	Enabled    bool                  `mapstructure:"enabled"`
	Audience   string                `mapstructure:"audience"`
	IssuerJWKS []HttpServerJWTIssuer `mapstructure:"issuer_jwks"`
	// IssuerJWKSURLs es el formato antiguo (mapa issuer -> JWKS URL).
	//
	// Deprecated: viper pasa a minúsculas las claves de mapa, así que un
	// issuer con mayúsculas no coincide con el iss del token. Usar IssuerJWKS;
	// se mantiene solo durante la transición.
	IssuerJWKSURLs    map[string]string `mapstructure:"issuer_jwks_urls"`
	AllowedAlgorithms []string          `mapstructure:"allowed_algorithms"`
	JWKSCacheTTL      time.Duration     `mapstructure:"jwks_cache_ttl"`
}

// HttpServerJWTIssuer es un issuer JWT de confianza y la URL de su JWKS. El
// issuer es un valor, no una clave de mapa: se conserva exacto (mayúsculas y
// puntos incluidos) y debe coincidir con el iss del token.
type HttpServerJWTIssuer struct {
	Issuer  string `mapstructure:"issuer"`
	JWKSURL string `mapstructure:"jwks_url"`
}

// ResolveIssuerJWKS devuelve el mapa issuer -> JWKS URL de la configuración.
// Acepta issuer_jwks o, durante la transición, issuer_jwks_urls (deprecated
// es true en ese caso); definir ambos es un error de configuración.
func (c HttpServerJWTAuthentication) ResolveIssuerJWKS() (issuers map[string]string, deprecated bool, err error) {
	if len(c.IssuerJWKS) > 0 && len(c.IssuerJWKSURLs) > 0 {
		return nil, false, errors.New("JWT authentication defines both issuer_jwks and the deprecated issuer_jwks_urls: keep only issuer_jwks")
	}
	if len(c.IssuerJWKSURLs) > 0 {
		return c.IssuerJWKSURLs, true, nil
	}
	issuers = make(map[string]string, len(c.IssuerJWKS))
	for i, entry := range c.IssuerJWKS {
		if entry.Issuer == "" {
			return nil, false, fmt.Errorf("issuer_jwks[%d]: issuer must not be empty", i)
		}
		if _, duplicated := issuers[entry.Issuer]; duplicated {
			return nil, false, fmt.Errorf("issuer_jwks[%d]: issuer %q is duplicated", i, entry.Issuer)
		}
		issuers[entry.Issuer] = entry.JWKSURL
	}
	return issuers, false, nil
}

type HttpServerVersioning struct {
	V1DefaultTenantID string    `mapstructure:"v1_default_tenant_id"`
	V1SunsetAt        time.Time `mapstructure:"v1_sunset_at"`
}

type HttpServerMutualTLSAuthentication struct {
	Enabled           bool          `mapstructure:"enabled"`
	ValidationMode    MutualTLSMode `mapstructure:"validation_mode"`
	CACertificateFile string        `mapstructure:"ca_cert_file"`
}

type MutualTLSMode string

const (
	Strict  MutualTLSMode = "strict"
	Request MutualTLSMode = "request"
	Any     MutualTLSMode = "any"
)

// HTTPClient is the configuration for the HTTP client

type HTTPClient struct {
	LogLevel          LogLevel             `mapstructure:"log_level"`
	AuthMode          HTTPClientAuthMethod `mapstructure:"auth_mode"`
	AuthJWTOptions    AuthJWTOptions       `mapstructure:"jwt_options"`
	AuthMTLSOptions   AuthMTLSOptions      `mapstructure:"mtls_options"`
	AuthApiKeyOptions AuthApiKeyOptions    `mapstructure:"apikey_options"`
	HTTPConnection    `mapstructure:",squash"`
}

// Authentication related config
type AuthJWTOptions struct {
	ClientID         string   `mapstructure:"oidc_client_id"`
	ClientSecret     Password `mapstructure:"oidc_client_secret"`
	OIDCWellKnownURL string   `mapstructure:"oidc_well_known"`
}

type AuthMTLSOptions struct {
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

type AuthMTLSInMemoryOptions struct {
	CertPEM []byte `mapstructure:"cert"`
	KeyPEM  []byte `mapstructure:"key"`
}

type AuthApiKeyOptions struct {
	Key    string `mapstructure:"key"`
	Header string `mapstructure:"header"`
}

type HTTPClientAuthMethod string

const (
	JWT    HTTPClientAuthMethod = "jwt"
	ApiKey HTTPClientAuthMethod = "apikey"
	MTLS   HTTPClientAuthMethod = "mtls"
	NoAuth HTTPClientAuthMethod = "noauth"
)
