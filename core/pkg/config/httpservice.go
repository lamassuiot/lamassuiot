package config

type HTTPConnection struct {
	Protocol        HTTPProtocol `mapstructure:"protocol" json:"protocol,omitempty"`
	BasePath        string       `mapstructure:"base_path" json:"base_path,omitempty"`
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
	LogLevel          LogLevel             `mapstructure:"log_level" json:"log_level,omitempty"`
	AuthMode          HTTPClientAuthMethod `mapstructure:"auth_mode" json:"auth_mode"`
	AuthJWTOptions    AuthJWTOptions       `mapstructure:"jwt_options" json:"jwt_options"`
	AuthMTLSOptions   AuthMTLSOptions      `mapstructure:"mtls_options" json:"mtls_options"`
	AuthApiKeyOptions AuthApiKeyOptions    `mapstructure:"apikey_options" json:"apikey_options"`
	HTTPConnection    `mapstructure:",squash"`
}

// Authentication related config
type AuthJWTOptions struct {
	ClientID         string   `mapstructure:"oidc_client_id" json:"oidc_client_id"`
	ClientSecret     Password `mapstructure:"oidc_client_secret" json:"oidc_client_secret"`
	OIDCWellKnownURL string   `mapstructure:"oidc_well_known" json:"oidc_well_known"`
}

// AuthMTLSOptions loads the client certificate from CertContent/KeyContent
// (PEM) when set, otherwise from CertFile/KeyFile.
type AuthMTLSOptions struct {
	CertFile    string `mapstructure:"cert_file" json:"cert_file,omitempty"`
	KeyFile     string `mapstructure:"key_file" json:"key_file,omitempty"`
	CertContent string `mapstructure:"cert_content" json:"cert_content,omitempty"`
	KeyContent  string `mapstructure:"key_content" json:"key_content,omitempty"`
}

type AuthApiKeyOptions struct {
	Key    string `mapstructure:"key" json:"key"`
	Header string `mapstructure:"header" json:"header"`
}

type HTTPClientAuthMethod string

const (
	JWT    HTTPClientAuthMethod = "jwt"
	ApiKey HTTPClientAuthMethod = "apikey"
	MTLS   HTTPClientAuthMethod = "mtls"
	NoAuth HTTPClientAuthMethod = "noauth"
)
