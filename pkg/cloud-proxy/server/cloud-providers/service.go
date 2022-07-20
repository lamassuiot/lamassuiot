package cloudproviders

import "context"

type Service interface {
	RegisterCA(ctx context.Context, caName string, caSerialNumber string, caCertificate string) error

	AttachAccessPolicy(ctx context.Context, caName string, caSerialNumber string, serializedAccessPolicy string) error
	GetConfiguration(ctx context.Context) (interface{}, []CloudProviderCAConfig, error)
	GetDeviceConfiguration(ctx context.Context, deviceID string) (interface{}, error)

	UpdateCaStatus(ctx context.Context, caName string, status string, certificateID string) error
	UpdateCertStatus(ctx context.Context, caName string, certSerialNumber string, status string, deviceCert string, caCert string) error
}
