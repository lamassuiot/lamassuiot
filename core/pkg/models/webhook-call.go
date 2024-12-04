package models

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
)

type WebhookCall struct {
	Name   string            `json:"name"`
	Url    string            `json:"url"`
	Config config.HTTPClient `json:"config"`
}
