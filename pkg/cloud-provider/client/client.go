package client

import (
	"context"
	"fmt"

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
	UpdateDeviceDigitalTwinStatus(ctx context.Context, input *api.UpdateDeviceDigitalTwinReenrollmentStatusInput) (*api.UpdateDeviceDigitalTwinReenrollmentStatusOutput, error)
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
	var output api.GetConfigurationOutputSerialized

	req, err := c.client.NewRequest(ctx, "POST", "v1/ca", input.CACertificate.Serialize())
	if err != nil {
		return &api.RegisterCAOutput{}, err
	}

	_, err = c.client.Do(req, &output)
	if err != nil {
		return &api.RegisterCAOutput{}, err
	}

	return &api.RegisterCAOutput{}, err
}

func (c *cloudProviderConfig) UpdateConfiguration(ctx context.Context, input *api.UpdateConfigurationInput) (*api.UpdateConfigurationOutput, error) {
	var output api.GetConfigurationOutputSerialized

	req, err := c.client.NewRequest(ctx, "PUT", "v1/config", input.Configuration)
	if err != nil {
		return &api.UpdateConfigurationOutput{}, err
	}

	_, err = c.client.Do(req, &output)
	if err != nil {
		return &api.UpdateConfigurationOutput{}, err
	}

	return &api.UpdateConfigurationOutput{}, err
}

func (c *cloudProviderConfig) GetConfiguration(ctx context.Context, input *api.GetConfigurationInput) (*api.GetConfigurationOutput, error) {
	var output api.GetConfigurationOutputSerialized

	req, err := c.client.NewRequest(ctx, "GET", "v1/config", nil)
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
	req, err := c.client.NewRequest(ctx, "GET", fmt.Sprintf("v1/devices/%s/config", input.DeviceID), nil)
	if err != nil {
		return nil, err
	}

	var output interface{}
	_, err = c.client.Do(req, &output)
	if err != nil {
		return nil, err
	}

	return &api.GetDeviceConfigurationOutput{
		Configuration: output,
	}, err
}

func (c *cloudProviderConfig) UpdateCAStatus(ctx context.Context, input *api.UpdateCAStatusInput) (*api.UpdateCAStatusOutput, error) {
	return nil, nil
}

func (c *cloudProviderConfig) UpdateDeviceCertificateStatus(ctx context.Context, input *api.UpdateDeviceCertificateStatusInput) (*api.UpdateDeviceCertificateStatusOutput, error) {
	var output api.GetDeviceConfigurationOutputSerialized

	req, err := c.client.NewRequest(ctx, "PUT", fmt.Sprintf("v1/devices/%s/certificate", input.DeviceID), api.UpdateDeviceCertificateStatusPayload{
		CAName:       input.CAName,
		SerialNumber: input.SerialNumber,
		Status:       input.Status,
	})
	if err != nil {
		return &api.UpdateDeviceCertificateStatusOutput{}, err
	}

	_, err = c.client.Do(req, &output)
	if err != nil {
		return &api.UpdateDeviceCertificateStatusOutput{}, err
	}

	return &api.UpdateDeviceCertificateStatusOutput{}, err
}
func (c *cloudProviderConfig) UpdateDeviceDigitalTwinStatus(ctx context.Context, input *api.UpdateDeviceDigitalTwinReenrollmentStatusInput) (*api.UpdateDeviceDigitalTwinReenrollmentStatusOutput, error) {
	var output api.GetDeviceConfigurationOutputSerialized

	req, err := c.client.NewRequest(ctx, "PUT", fmt.Sprintf("v1/devices/%s/digital-twin", input.DeviceID), api.UpdateDeviceDigitalTwinReenrollmentStatusPayload{
		SlotID:        input.SlotID,
		ForceReenroll: input.ForceReenroll,
	})
	if err != nil {
		return &api.UpdateDeviceDigitalTwinReenrollmentStatusOutput{}, err
	}

	_, err = c.client.Do(req, &output)
	if err != nil {
		return &api.UpdateDeviceDigitalTwinReenrollmentStatusOutput{}, err
	}

	return &api.UpdateDeviceDigitalTwinReenrollmentStatusOutput{}, err
}
