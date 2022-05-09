package instances

import (
	"context"
	"errors"
	"fmt"

	cloudproviders "github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/cloud-providers"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/cloud-providers/instances/aws"

	"github.com/go-kit/kit/log"
)

type Service interface {
	RegisterCA(ctx context.Context, caName string, caSerialNumber string, caCertificate string) error

	AttachAccessPolicy(ctx context.Context, caName string, caSerialNumber string, serializedAccessPolicy string) error
	GetConfiguration(ctx context.Context) (interface{}, []cloudproviders.CloudProviderCAConfig, error)
	GetDeviceConfiguration(ctx context.Context, deviceID string) (interface{}, error)

	UpdateCaStatus(ctx context.Context, caName string, status string, certificateID string) error
	UpdateCertStatus(ctx context.Context, caName string, certSerialNumber string, status string, deviceCert string, caCert string) error
}

func NewCloudConnectorService(id string, ip string, port string, cloudProviderType cloudproviders.CloudProvider, logger log.Logger) (Service, error) {
	switch cloudProviderType {
	case cloudproviders.CloudProvider_AmazonWebServices:
		return aws.NewAwsConnectorClient(id, ip, port, logger), nil
	// case cloudproviders.MicrosoftAzure:
	// 	return azure.NewAzureConnectorClient(ip, port, logger), nil
	// case cloudproviders.GoogleCloud:
	// 	return gcloud.NewGcloudConnectorClient(ip, port, logger), nil
	default:
		s := fmt.Sprint("unsupported cloud provider type: ", cloudProviderType)
		return nil, errors.New(s)
	}
}

func NewCloudConnectorServiceFromCloudConnector(connector cloudproviders.CloudConnector, logger log.Logger) (Service, error) {
	connectorType, err := cloudproviders.ParseCloudProviderType(connector.CloudProvider)
	if err != nil {
		return nil, err
	}

	switch connectorType {
	case cloudproviders.CloudProvider_AmazonWebServices:
		return aws.NewAwsConnectorClient(connector.ID, connector.IP, connector.Port, logger), nil
	// case cloudproviders.MicrosoftAzure:
	// 	return azure.NewAzureConnectorClient(connector.IP, connector.Port, logger), nil
	// case cloudproviders.GoogleCloud:
	// 	return gcloud.NewGcloudConnectorClient(connector.IP, connector.Port, logger), nil
	default:
		s := fmt.Sprint("unsupported cloud provider type: ", connectorType)
		return nil, errors.New(s)
	}
}
