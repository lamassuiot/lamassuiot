package client

import (
	"context"
	"encoding/json"

	cloudproviders "github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/cloud-providers"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
)

type LamassuCloudProxyClient interface {
	GetCloudConnectors(ctx context.Context) ([]cloudproviders.CloudConnector, error)
	// GetCloudConnectorByID(ctx context.Context, cloudConnectorID string) (cloudproviders.CloudConnector, error)
	// GetDeviceConfiguration(ctx context.Context, cloudConnectorID string, deviceID string) (interface{}, error)
	// SynchronizeCA(ctx context.Context, cloudConnectorID string, caName string, enabledTs time.Time) (cloudproviders.CloudConnector, error)
	// UpdateSecurityAccessPolicy(ctx context.Context, cloudConnectorID string, caName string, serializedSecurityAccessPolicy string) (cloudproviders.CloudConnector, error)

	// HandleCreateCAEvent(ctx context.Context, caName string, caSerialNumber string, caCertificate string) error
	// HandleUpdateCaStatusEvent(ctx context.Context, caName string, status string) error
	// HandleUpdateCertStatusEvent(ctx context.Context, caName string, serialNumber string, status string) error
	// UpdateCertStatus(ctx context.Context, deviceID string, certSerialNumber string, status string, connectorID string, caName string) error
	// UpdateCaStatus(ctx context.Context, caName string, status string) error
}

type lamassuCloudProxyClientConfig struct {
	client clientUtils.BaseClient
}

func NewLamassuCloudProxyClient(config clientUtils.ClientConfiguration) (LamassuCloudProxyClient, error) {
	baseClient, err := clientUtils.NewBaseClient(config)
	if err != nil {
		return nil, err
	}

	return &lamassuCloudProxyClientConfig{
		client: baseClient,
	}, nil
}

func (c *lamassuCloudProxyClientConfig) GetCloudConnectors(ctx context.Context) ([]cloudproviders.CloudConnector, error) {
	req, err := c.client.NewRequest("GET", "v1/connectors", nil)
	if err != nil {
		return make([]cloudproviders.CloudConnector, 0), err
	}
	respBody, _, err := c.client.Do(req)
	if err != nil {
		return make([]cloudproviders.CloudConnector, 0), err
	}

	connectorsInterface := respBody.([]interface{})
	var connectors []cloudproviders.CloudConnector
	for _, item := range connectorsInterface {
		var connector cloudproviders.CloudConnector
		jsonString, _ := json.Marshal(item)
		json.Unmarshal(jsonString, &connector)
		connectors = append(connectors, connector)
	}

	return connectors, nil
}
