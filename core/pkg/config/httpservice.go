package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

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
	// ReadTimeout and WriteTimeout bound a whole request read and response write, written as Go durations such
	// as "30s". Zero means DefaultHTTPServerTimeout; nonzero values below MinConfigDuration are rejected.
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

// DefaultHTTPServerTimeout is the read and write timeout applied when none is configured.
const DefaultHTTPServerTimeout = 10 * time.Second

// MinConfigDuration is the smallest nonzero duration accepted by CheckDuration.
const MinConfigDuration = time.Second

// CheckDuration validates a duration setting where 0 selects the default. It rejects negative values and nonzero
// values below MinConfigDuration: a YAML integer without a unit decodes as nanoseconds, so a value such as 30
// (meant as 30 s) would otherwise start the service with a 30 ns setting.
func CheckDuration(key string, d time.Duration) error {
	if d < 0 {
		return fmt.Errorf("%s must not be negative, got %s", key, d)
	}
	if d > 0 && d < MinConfigDuration {
		err := fmt.Errorf("%s must be 0 (default) or at least %s, got %s", key, MinConfigDuration, d)
		// Below a millisecond the value almost certainly came from an integer without a unit.
		if d < time.Millisecond {
			err = fmt.Errorf("%w; a number without a unit is read as nanoseconds, write it with a unit such as \"30s\"", err)
		}
		return err
	}
	return nil
}

// ServerTimeouts returns the effective read and write timeouts, applying DefaultHTTPServerTimeout to unset values.
func (c HttpServer) ServerTimeouts() (read, write time.Duration, err error) {
	if err := CheckDuration("server.read_timeout", c.ReadTimeout); err != nil {
		return 0, 0, err
	}
	if err := CheckDuration("server.write_timeout", c.WriteTimeout); err != nil {
		return 0, 0, err
	}
	read, write = c.ReadTimeout, c.WriteTimeout
	if read == 0 {
		read = DefaultHTTPServerTimeout
	}
	if write == 0 {
		write = DefaultHTTPServerTimeout
	}
	return read, write, nil
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
// when set, otherwise from CertFile/KeyFile. For backwards compatibility,
// CertFile/KeyFile may also hold PEM content directly.
//
// CertContent/KeyContent hold base64-encoded PEM, like certificates elsewhere
// in the API. Plain PEM is also accepted, as written by earlier configs.
type AuthMTLSOptions struct {
	CertFile    string `mapstructure:"cert_file" json:"cert_file,omitempty"`
	KeyFile     string `mapstructure:"key_file" json:"key_file,omitempty"`
	CertContent string `mapstructure:"cert_content" json:"cert_content,omitempty"`
	KeyContent  string `mapstructure:"key_content" json:"key_content,omitempty"`
}

// ContentPEM returns CertContent and KeyContent decoded to PEM.
func (o AuthMTLSOptions) ContentPEM() (cert, key []byte, err error) {
	if cert, err = decodePEMContent("cert_content", o.CertContent); err != nil {
		return nil, nil, err
	}
	if key, err = decodePEMContent("key_content", o.KeyContent); err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func decodePEMContent(field, value string) ([]byte, error) {
	if strings.Contains(value, "-----BEGIN") {
		return []byte(value), nil
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || !bytes.Contains(decoded, []byte("-----BEGIN")) {
		return nil, fmt.Errorf("mtls_options.%s must be base64-encoded PEM", field)
	}
	return decoded, nil
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
