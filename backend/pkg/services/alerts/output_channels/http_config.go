package outputchannels

import (
	"context"
	"encoding/json"
	"fmt"

	webhookclient "github.com/lamassuiot/lamassuiot/v4/backend/pkg/helpers/webhook-client"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
)

// Notification channels always authenticate HTTPS servers using the system
// trust store. Client authentication is optional for URL-secret webhooks.
// Reserved API key headers are rejected by the webhook client itself.
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

// sendHTTPNotification delivers an already-encoded notification body to an
// HTTP channel using the notification client policy.
func sendHTTPNotification(ctx context.Context, logger *logrus.Entry, name, url, method string, options *models.WebhookCallHttpClient, body []byte) error {
	httpConfig, err := notificationHTTPConfig(options)
	if err != nil {
		return err
	}

	_, err = webhookclient.InvokeWebhook(ctx, logger, models.WebhookCall{
		Name:   name,
		Url:    url,
		Method: method,
		Config: httpConfig,
	}, body)
	return err
}

// decodeChannelConfig converts a stored channel config (decoded as generic
// JSON) into its typed form.
func decodeChannelConfig[T any](c models.Channel) (T, error) {
	var cfg T
	b, err := json.Marshal(c.Config)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(b, &cfg)
	return cfg, err
}
