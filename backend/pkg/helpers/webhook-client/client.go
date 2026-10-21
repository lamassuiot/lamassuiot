package webhookclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/sdk"
	"github.com/sirupsen/logrus"
)

// DefaultCallTimeout bounds a webhook call (including OIDC discovery and token
// retrieval) when the webhook does not configure call_timeout.
const DefaultCallTimeout = 10 * time.Second

// MaxResponseBodySize caps how much of a webhook response is read into memory.
const MaxResponseBodySize = 1 << 20

// ValidateConfig rejects webhook client options that are unsafe for
// user-supplied configs: anything that makes the service read its own files
// and API key headers that receiving services trust.
func ValidateConfig(cfg models.WebhookCallHttpClient) error {
	mtls := cfg.AuthMTLSOptions
	if cfg.CACertificateFile != "" || mtls.CertFile != "" || mtls.KeyFile != "" {
		return errors.New("webhook config must not reference files: use mtls_options.cert_content and mtls_options.key_content")
	}

	switch cfg.AuthMode {
	case config.ApiKey:
		if isReservedHeader(cfg.AuthApiKeyOptions.Header) {
			return fmt.Errorf("webhook API key header %q is reserved", cfg.AuthApiKeyOptions.Header)
		}
	case config.MTLS:
		if mtls.CertContent == "" || mtls.KeyContent == "" {
			return errors.New("webhook mTLS requires mtls_options.cert_content and mtls_options.key_content")
		}
	}

	return nil
}

func InvokeWebhook(ctx context.Context, logger *logrus.Entry, conf models.WebhookCall, payload []byte) ([]byte, error) {
	timeout := DefaultCallTimeout
	if conf.Config.CallTimeout > 0 {
		timeout = time.Duration(conf.Config.CallTimeout)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := ValidateConfig(conf.Config); err != nil {
		return nil, err
	}

	lCli := logger.WithField("webhook", fmt.Sprintf("webhook-cli: %s", conf.Name))
	cli, err := sdk.BuildHTTPClientWithContext(ctx, conf.Config.HTTPClient, lCli)
	if err != nil {
		return nil, err
	}

	method := "POST"
	if conf.Method != "" {
		// Allow only POST and PUT methods
		if conf.Method != "POST" && conf.Method != "PUT" {
			return nil, fmt.Errorf("invalid method: %s", conf.Method)
		}
		method = conf.Method
	}

	req, err := http.NewRequestWithContext(ctx, method, conf.Url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	// Both enrollment decisions and notification webhooks send JSON.
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(res.Body, MaxResponseBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(bodyBytes) > MaxResponseBodySize {
		return nil, fmt.Errorf("webhook response exceeds %d bytes", MaxResponseBodySize)
	}

	return bodyBytes, nil
}

func InvokeJSONWebhook[E any](ctx context.Context, logger *logrus.Entry, config models.WebhookCall, payload any) (*E, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	res, err := InvokeWebhook(ctx, logger, config, b)
	if err != nil {
		return nil, err
	}

	data, err := sdk.ParseJSON[E](res)
	if err != nil {
		return nil, err
	}

	return &data, nil
}
