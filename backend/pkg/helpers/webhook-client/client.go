package webhookclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
	"github.com/sirupsen/logrus"
)

func InvokeWebhook(ctx context.Context, logger *logrus.Entry, conf models.WebhookCall, payload []byte) ([]byte, error) {
	clientConfig := config.HTTPClient{
		LogLevel: config.LogLevel(conf.Config.LogLevel),
		AuthMode: conf.Config.AuthMode,
		HTTPConnection: config.HTTPConnection{
			BasicConnection: config.BasicConnection{
				TLSConfig: config.TLSConfig{
					InsecureSkipVerify: !conf.Config.ValidateServerCert,
				},
			},
		},
	}

	if conf.Config.AuthMode == config.JWT {
		clientConfig.AuthJWTOptions = config.AuthJWTOptions{
			ClientID:         conf.Config.OIDC.ClientID,
			ClientSecret:     config.Password(conf.Config.OIDC.ClientSecret),
			OIDCWellKnownURL: conf.Config.OIDC.OIDCWellKnownURL,
		}
	} else if conf.Config.AuthMode == config.ApiKey {
		clientConfig.AuthApiKeyOptions = config.AuthApiKeyOptions{
			Key:    conf.Config.ApiKey.Key,
			Header: conf.Config.ApiKey.Header,
		}
	} else if conf.Config.AuthMode == config.MTLS {
		clientConfig.AuthMTLSOptions = config.AuthMTLSOptions{
			CertFile: conf.Config.MutualTLS.Cert,
			KeyFile:  conf.Config.MutualTLS.Key,
		}
	}

	lCli := logger.WithField("webhook", fmt.Sprintf("webhook-cli: %s", conf.Name))
	cli, err := sdk.BuildHTTPClient(clientConfig, lCli)
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

	res, err := cli.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	respBody := new(bytes.Buffer)
	_, err = respBody.ReadFrom(res.Body)
	if err != nil {
		return nil, err
	}

	bodyBytes := respBody.Bytes()
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
