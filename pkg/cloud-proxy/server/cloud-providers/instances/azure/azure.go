package azure

import (
	"context"
	"fmt"

	"github.com/go-kit/kit/log"
	"github.com/lamassuiot/lamassu-azure-connector/pkg/client"

	cloudproviders "github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/cloud-providers"
)

type AzureConnectorSettings struct {
	logger log.Logger
	ID     string
	IP     string
	Port   string
}

func NewAzureConnectorClient(id string, ip string, port string, logger log.Logger) cloudproviders.Service {
	return &AzureConnectorSettings{
		logger: logger,
		IP:     ip,
		Port:   port,
		ID:     id,
	}
}

func (s *AzureConnectorSettings) RegisterCA(ctx context.Context, caName string, caSerialNumber string, caCertificate string) error {
	fmt.Println("Registering CA with AZURE Connector")
	azureClient, err := client.NewAzureConnectorClient(s.ID, s.IP, s.Port, s.logger)
	if err != nil {
		return err
	}
	err = azureClient.RegisterCA(ctx, caName, caSerialNumber, caCertificate)
	if err != nil {
		return err
	}
	return nil
}

func (s *AzureConnectorSettings) AttachAccessPolicy(ctx context.Context, caName string, caSerialNumber string, serializedAccessPolicy string) error {
	return nil
}

func (s *AzureConnectorSettings) GetConfiguration(ctx context.Context) (interface{}, []cloudproviders.CloudProviderCAConfig, error) {
	cas := make([]cloudproviders.CloudProviderCAConfig, 0)
	return nil, cas, nil
}

func (s *AzureConnectorSettings) UpdateCaStatus(ctx context.Context, caName string, status string, certificateID string) error {
	return nil
}

func (s *AzureConnectorSettings) UpdateCertStatus(ctx context.Context, caName string, certSerialNumber string, status string, deviceCert string, caCert string) error {
	return nil
}

func (s *AzureConnectorSettings) GetDeviceConfiguration(ctx context.Context, deviceID string) (interface{}, error) {
	return nil, nil
}
