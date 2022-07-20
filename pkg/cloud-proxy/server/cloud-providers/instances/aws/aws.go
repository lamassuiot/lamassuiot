package aws

import (
	"context"
	"fmt"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassu-aws-connector/pkg/client"
	cloudproviders "github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/cloud-providers"
)

type IotCoreCAConfig struct {
	ID               string `json:"id"`
	ARN              string `json:"arn"`
	RegistrationDate string `json:"registration_date"`
	ActivePolicy     string `json:"active_policy"`
}

type IotCoreConfig struct {
	Endpoint string          `json:"endpoint"`
	CA       IotCoreCAConfig `json:"ca"`
}

type AwsConfiguration struct {
	AccountID string        `json:"account_id"`
	IotCore   IotCoreConfig `json:"iot_core"`
}

type AwsConnectorSettings struct {
	logger log.Logger
	ID     string
	IP     string
	Port   string
}

func NewAwsConnectorClient(id string, ip string, port string, logger log.Logger) cloudproviders.Service {

	return &AwsConnectorSettings{
		logger: logger,
		ID:     id,
		IP:     ip,
		Port:   port,
	}
}

func (s *AwsConnectorSettings) RegisterCA(ctx context.Context, caName string, caSerialNumber string, caCertificate string) error {
	level.Info(s.logger).Log("msg", "Resgitering CA to AWS")
	awsClient, err := client.NewAwsConnectorClient(s.ID, s.IP, s.Port, s.logger)
	if err != nil {
		return err
	}
	err = awsClient.RegisterCA(ctx, caName, caSerialNumber, caCertificate)
	if err != nil {
		return err
	}
	return nil
}

func (s *AwsConnectorSettings) AttachAccessPolicy(ctx context.Context, caName string, caSerialNumber string, serializedAccessPolicy string) error {
	fmt.Println("Calling attach access policy", s.ID, caName, serializedAccessPolicy)

	awsClient, err := client.NewAwsConnectorClient(s.ID, s.IP, s.Port, s.logger)
	if err != nil {
		return err
	}
	err = awsClient.AttachAccessPolicy(ctx, caName, caSerialNumber, serializedAccessPolicy)
	if err != nil {
		return err
	}
	return nil
}

func (s *AwsConnectorSettings) GetConfiguration(ctx context.Context) (interface{}, []cloudproviders.CloudProviderCAConfig, error) {
	cas := make([]cloudproviders.CloudProviderCAConfig, 0)

	awsClient, err := client.NewAwsConnectorClient(s.ID, s.IP, s.Port, s.logger)
	if err != nil {
		return nil, nil, err
	}
	config, err := awsClient.GetConfiguration(ctx)
	if err != nil {
		return nil, nil, err
	}

	for _, awsCA := range config.CAs {
		cas = append(cas, cloudproviders.CloudProviderCAConfig{
			CAName: awsCA.CAName,
			Config: awsCA,
		})
	}

	return struct {
		IotCoreEndpoint string `json:"iot_core_endpoint"`
		AccountID       string `json:"account_id"`
	}{
		IotCoreEndpoint: config.IotCoreEndpoint,
		AccountID:       config.AccountID,
	}, cas, nil
}

func (s *AwsConnectorSettings) UpdateCaStatus(ctx context.Context, caName string, status string, certificateID string) error {

	awsClient, err := client.NewAwsConnectorClient(s.ID, s.IP, s.Port, s.logger)
	if err != nil {
		return err
	}
	err = awsClient.UpdateCaStatus(ctx, caName, status, certificateID)
	if err != nil {
		return err
	}

	return nil
}
func (s *AwsConnectorSettings) UpdateCertStatus(ctx context.Context, caName string, certSerialNumber string, status string, deviceCert string, caCert string) error {

	awsClient, err := client.NewAwsConnectorClient(s.ID, s.IP, s.Port, s.logger)
	if err != nil {
		return err
	}
	err = awsClient.UpdateCertStatus(ctx, caName, certSerialNumber, status, deviceCert, caCert)
	if err != nil {
		return err
	}

	return nil
}
func (s *AwsConnectorSettings) GetDeviceConfiguration(ctx context.Context, deviceID string) (interface{}, error) {
	awsClient, err := client.NewAwsConnectorClient(s.ID, s.IP, s.Port, s.logger)
	if err != nil {
		return nil, err
	}
	config, err := awsClient.GetDeviceConfiguration(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	return config, nil
}
