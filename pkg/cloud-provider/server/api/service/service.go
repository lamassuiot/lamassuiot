package service

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/cloud-provider/common/api"
)

type Service interface {
	Health() bool
	RegisterCA(ctx context.Context, input *api.RegisterCAInput) (*api.RegisterCAOutput, error)
	UpdateConfiguration(ctx context.Context, input *api.UpdateConfigurationInput) (*api.UpdateConfigurationOutput, error)
	GetConfiguration(ctx context.Context, input *api.GetConfigurationInput) (*api.GetConfigurationOutput, error)
	GetDeviceConfiguration(ctx context.Context, input *api.GetDeviceConfigurationInput) (*api.GetDeviceConfigurationOutput, error)
	UpdateCAStatus(ctx context.Context, input *api.UpdateCAStatusInput) (*api.UpdateCAStatusOutput, error)
	UpdateDMSCaCerts(ctx context.Context, input *api.UpdateDMSCaCertsInput) (*api.UpdateDMSCaCertsOutput, error)
	UpdateDeviceCertificateStatus(ctx context.Context, input *api.UpdateDeviceCertificateStatusInput) (*api.UpdateDeviceCertificateStatusOutput, error)
	UpdateDeviceDigitalTwinReenrollmentStatus(ctx context.Context, input *api.UpdateDeviceDigitalTwinReenrollmentStatusInput) (*api.UpdateDeviceDigitalTwinReenrollmentStatusOutput, error)
}
