package outputchannels

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	webhookclient "github.com/lamassuiot/lamassuiot/v4/backend/pkg/helpers/webhook-client"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
)

// maxNotificationCallTimeout bounds how long a single notification channel can
// stall alert delivery to the remaining subscribers of an event.
const maxNotificationCallTimeout = 30 * time.Second

// Notification channels always authenticate HTTPS servers using the system
// trust store. Client authentication is optional for URL-secret webhooks.
// Reserved API key headers are rejected by the webhook client itself.
func notificationHTTPConfig(options *models.WebhookCallHttpClient) (models.WebhookCallHttpClient, error) {
	var cfg models.WebhookCallHttpClient
	if options != nil {
		cfg = *options
	}
	cfg.InsecureSkipVerify = false
	if cfg.AuthMode == "" {
		cfg.AuthMode = config.NoAuth
	}
	if time.Duration(cfg.CallTimeout) > maxNotificationCallTimeout {
		cfg.CallTimeout = models.TimeDuration(maxNotificationCallTimeout)
	}
	switch cfg.AuthMode {
	case config.NoAuth, config.ApiKey, config.JWT, config.MTLS:
		return cfg, nil
	default:
		return cfg, fmt.Errorf("unsupported notification authentication mode: %s", cfg.AuthMode)
	}
}

// ValidateChannel checks the URL, method and HTTP client options of webhook
// and MS Teams channels with the same policy used to deliver them, so invalid
// configs are rejected when the subscription is created instead of failing on
// every event delivery.
func ValidateChannel(c models.Channel) error {
	var call models.WebhookCall
	var options *models.WebhookCallHttpClient
	switch c.Type {
	case models.ChannelTypeWebhook:
		cfg, err := decodeChannelConfig[models.WebhookChannelConfig](c)
		if err != nil {
			return fmt.Errorf("invalid webhook channel config: %w", err)
		}
		call = models.WebhookCall{Url: cfg.WebhookURL, Method: cfg.WebhookMethod}
		options = cfg.HTTPClient
	case models.ChannelTypeMSTeams:
		cfg, err := decodeChannelConfig[models.MSTeamsChannelConfig](c)
		if err != nil {
			return fmt.Errorf("invalid MS Teams channel config: %w", err)
		}
		call = models.WebhookCall{Url: cfg.WebhookURL, Method: http.MethodPost}
		options = cfg.HTTPClient
	default:
		return nil
	}

	httpConfig, err := notificationHTTPConfig(options)
	if err != nil {
		return err
	}
	call.Config = httpConfig
	return webhookclient.ValidateWebhook(call)
}

// sendHTTPNotification delivers an already-encoded notification body to an
// HTTP channel using the notification client policy.
func sendHTTPNotification(ctx context.Context, logger *logrus.Entry, name, url, method string, options *models.WebhookCallHttpClient, body []byte) error {
	httpConfig, err := notificationHTTPConfig(options)
	if err != nil {
		return err
	}

	return webhookclient.InvokeWebhook(ctx, logger, models.WebhookCall{
		Name:   name,
		Url:    url,
		Method: method,
		Config: httpConfig,
	}, body)
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
