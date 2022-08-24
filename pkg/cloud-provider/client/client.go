package client

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/cloud-provider/common/api"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
)

type cloudProviderConfig struct {
	client clientUtils.BaseClient
}

type LamassuCloudProviderClient interface {
	RegisterCA(ctx context.Context, input *api.RegisterCAInput) (*api.RegisterCAOutput, error)
	UpdateConfiguration(ctx context.Context, input *api.UpdateConfigurationInput) (*api.UpdateConfigurationOutput, error)
	GetConfiguration(ctx context.Context, input *api.GetConfigurationInput) (*api.GetConfigurationOutput, error)
	GetDeviceConfiguration(ctx context.Context, input *api.GetDeviceConfigurationInput) (*api.GetDeviceConfigurationOutput, error)
	UpdateCAStatus(ctx context.Context, input *api.UpdateCAStatusInput) (*api.UpdateCAStatusOutput, error)
	UpdateDeviceCertificateStatus(ctx context.Context, input *api.UpdateDeviceCertificateStatusInput) (*api.UpdateDeviceCertificateStatusOutput, error)
}

func NewCloudProviderClient(config clientUtils.BaseClientConfigurationuration) (LamassuCloudProviderClient, error) {
	baseClient, err := clientUtils.NewBaseClient(config)
	if err != nil {
		return nil, err
	}

	return &cloudProviderConfig{
		client: baseClient,
	}, nil
}

func (c *cloudProviderConfig) RegisterCA(ctx context.Context, input *api.RegisterCAInput) (*api.RegisterCAOutput, error) {
	return nil, nil
}
func (c *cloudProviderConfig) UpdateConfiguration(ctx context.Context, input *api.UpdateConfigurationInput) (*api.UpdateConfigurationOutput, error) {
	return nil, nil
}
func (c *cloudProviderConfig) GetConfiguration(ctx context.Context, input *api.GetConfigurationInput) (*api.GetConfigurationOutput, error) {
	var output api.GetConfigurationOutputSerialized

	req, err := c.client.NewRequest("GET", "v1/config", nil)
	if err != nil {
		return &api.GetConfigurationOutput{}, err
	}

	_, err = c.client.Do(req, &output)
	if err != nil {
		return &api.GetConfigurationOutput{}, err
	}

	parsedCAConfigs := make([]api.CAConfiguration, 0)
	for _, caConfig := range output.CAsConfiguration {
		parsedCAConfigs = append(parsedCAConfigs, caConfig.Deserialize())
	}
	return &api.GetConfigurationOutput{
		Configuration:    output.Configuration,
		CAsConfiguration: parsedCAConfigs,
	}, err
}
func (c *cloudProviderConfig) GetDeviceConfiguration(ctx context.Context, input *api.GetDeviceConfigurationInput) (*api.GetDeviceConfigurationOutput, error) {
	return nil, nil
}
func (c *cloudProviderConfig) UpdateCAStatus(ctx context.Context, input *api.UpdateCAStatusInput) (*api.UpdateCAStatusOutput, error) {
	return nil, nil
}
func (c *cloudProviderConfig) UpdateDeviceCertificateStatus(ctx context.Context, input *api.UpdateDeviceCertificateStatusInput) (*api.UpdateDeviceCertificateStatusOutput, error) {
	return nil, nil
}
