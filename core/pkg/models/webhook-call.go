package models

import (
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
)

type WebhookCall struct {
	Name   string                `json:"name"`
	Url    string                `json:"url"`
	Method string                `json:"method"`
	Config WebhookCallHttpClient `json:"config"`
	// AllowedHeaders replaces the default EST request header allowlist when set.
	// An explicit empty list forwards no headers.
	AllowedHeaders *[]string `json:"allowed_headers,omitempty"`
}

type WebhookCallHttpClient struct {
	// Deprecated: HTTPS server verification is always enforced for webhooks.
	ValidateServerCert bool                             `json:"validate_server_cert"`
	LogLevel           string                           `json:"log_level"`
	AuthMode           config.HTTPClientAuthMethod      `json:"auth_mode"`
	CallTimeout        TimeDuration                     `json:"call_timeout,omitempty"`
	OIDC               WebhookCallHttpClientOidcOptions `json:"oidc"`
	ApiKey             WebhookCallHttpClientApiKey      `json:"apikey"`
	MutualTLS          WebhookCallHttpClientMutualTLS   `json:"mtls"`
}

type WebhookCallHttpClientOidcOptions struct {
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret"`
	OIDCWellKnownURL string `json:"well_known"`
}

type WebhookCallHttpClientApiKey struct {
	Key    string `json:"key"`
	Header string `json:"header"`
}

type WebhookCallHttpClientMutualTLS struct {
	// Cert and Key contain inline PEM. Server filesystem paths are not accepted.
	Cert string `json:"cert"`
	Key  string `json:"key"`
}
