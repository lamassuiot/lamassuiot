package models

import (
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
)

type WebhookCall struct {
	Name   string             `json:"name"`
	Url    string             `json:"url"`
	Config cconfig.HTTPClient `json:"config"`
}
