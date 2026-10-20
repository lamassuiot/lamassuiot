package outputchannels

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
)

// Notification channels always authenticate HTTPS servers using the system
// trust store. Client authentication is optional for URL-secret webhooks.
func notificationHTTPConfig(options *models.WebhookCallHttpClient) (models.WebhookCallHttpClient, error) {
	cfg := models.WebhookCallHttpClient{LogLevel: "INFO", AuthMode: config.NoAuth}
	if options != nil {
		cfg = *options
	}
	cfg.ValidateServerCert = true
	if cfg.LogLevel == "" {
		cfg.LogLevel = "INFO"
	}
	if cfg.AuthMode == "" {
		cfg.AuthMode = config.NoAuth
	}
	switch cfg.AuthMode {
	case config.NoAuth, config.ApiKey, config.JWT, config.MTLS:
		return cfg, nil
	default:
		return cfg, fmt.Errorf("unsupported notification authentication mode: %s", cfg.AuthMode)
	}
}
