package config

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
	LogLevel           LogLevel                 `mapstructure:"log_level"`
	HealthCheckLogging bool                     `mapstructure:"health_check"`
	ListenAddress      string                   `mapstructure:"listen_address"`
	Port               int                      `mapstructure:"port"`
	Protocol           HTTPProtocol             `mapstructure:"protocol"`
	CertFile           string                   `mapstructure:"cert_file"`
	KeyFile            string                   `mapstructure:"key_file"`
	Authentication     HttpServerAuthentication `mapstructure:"authentication"`
}

type HttpServerAuthentication struct {
	MutualTLS HttpServerMutualTLSAuthentication `mapstructure:"mutual_tls"`
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
