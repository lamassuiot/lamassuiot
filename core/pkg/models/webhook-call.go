package models

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
)

type WebhookCall struct {
	Name   string                `json:"name"`
	Url    string                `json:"url"`
	Config WebhookCallHttpClient `json:"config"`
}

type WebhookCallHttpClient struct {
	ValidateServerCert bool                             `json:"validate_server_cert"`
	LogLevel           string                           `json:"log_level"`
	AuthMode           config.HTTPClientAuthMethod      `json:"auth_mode"`
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
	Cert string `json:"cert`
	Key  string `json:"key"`
}
