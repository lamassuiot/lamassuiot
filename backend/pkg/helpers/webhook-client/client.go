package webhookclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
	"github.com/sirupsen/logrus"
)

func InvokeWebhook(logger *logrus.Entry, config models.WebhookCall, payload []byte) ([]byte, error) {
	lCli := logger.WithField("webhook", fmt.Sprintf("webhook-cli: %s", config.Name))
	cli, err := sdk.BuildHTTPClient(config.Config, lCli)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", config.Url, bytes.NewBuffer(payload))
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

func InvokeJSONWebhook[E any](logger *logrus.Entry, config models.WebhookCall, payload any) (*E, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	res, err := InvokeWebhook(logger, config, b)
	if err != nil {
		return nil, err
	}

	data, err := sdk.ParseJSON[E](res)
	if err != nil {
		return nil, err
	}

	return &data, nil
}
