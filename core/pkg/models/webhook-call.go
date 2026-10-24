package models

import (
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
)

type WebhookCall struct {
	Name   string                `json:"name"`
	Url    string                `json:"url"`
	Method string                `json:"method"`
	Config WebhookCallHttpClient `json:"config"`
}

// WebhookCallHttpClient is a user-supplied HTTP client configuration. Fields
// that reference files on the service filesystem are rejected when invoked.
type WebhookCallHttpClient struct {
	config.HTTPClient
	CallTimeout TimeDuration `json:"call_timeout,omitempty"`
}
