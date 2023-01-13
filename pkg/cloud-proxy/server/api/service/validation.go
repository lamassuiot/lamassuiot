package service

import (
	"context"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/errors"
)

type validationMiddleware struct {
	next Service
}

func NewInputValudationMiddleware() Middleware {
	return func(next Service) Service {
		return &validationMiddleware{
			next: next,
		}
	}
}

func (mw *validationMiddleware) Health(ctx context.Context) (healthy bool) {
	return mw.next.Health(ctx)
}

func (mw *validationMiddleware) GetCloudConnectors(ctx context.Context, input *api.GetCloudConnectorsInput) (output *api.GetCloudConnectorsOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.GetCloudConnectors(ctx, input)
}

func (mw *validationMiddleware) GetCloudConnectorByID(ctx context.Context, input *api.GetCloudConnectorByIDInput) (*api.GetCloudConnectorByIDOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.GetCloudConnectorByID(ctx, input)
}

func (mw *validationMiddleware) GetDeviceConfiguration(ctx context.Context, input *api.GetDeviceConfigurationInput) (*api.GetDeviceConfigurationOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.GetDeviceConfiguration(ctx, input)
}

func (mw *validationMiddleware) SynchronizeCA(ctx context.Context, input *api.SynchronizeCAInput) (*api.SynchronizeCAOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.SynchronizeCA(ctx, input)
}

func (mw *validationMiddleware) UpdateCloudProviderConfiguration(ctx context.Context, input *api.UpdateCloudProviderConfigurationInput) (*api.UpdateCloudProviderConfigurationOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.UpdateCloudProviderConfiguration(ctx, input)
}

func (mw *validationMiddleware) HandleCreateCAEvent(ctx context.Context, input *api.HandleCreateCAEventInput) (*api.HandleCreateCAEventOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.HandleCreateCAEvent(ctx, input)
}

func (mw *validationMiddleware) HandleUpdateCAStatusEvent(ctx context.Context, input *api.HandleUpdateCAStatusEventInput) (*api.HandleUpdateCAStatusEventOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.HandleUpdateCAStatusEvent(ctx, input)
}

func (mw *validationMiddleware) HandleUpdateCertificateStatusEvent(ctx context.Context, input *api.HandleUpdateCertificateStatusEventInput) (*api.HandleUpdateCertificateStatusEventOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.HandleUpdateCertificateStatusEvent(ctx, input)
}

func (mw *validationMiddleware) HandleReenrollEvent(ctx context.Context, input *api.HandleReenrollEventInput) (*api.HandleReenrollEventOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.HandleReenrollEvent(ctx, input)
}

func (mw *validationMiddleware) UpdateDeviceCertificateStatus(ctx context.Context, input *api.UpdateDeviceCertificateStatusInput) (*api.UpdateDeviceCertificateStatusOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.UpdateDeviceCertificateStatus(ctx, input)
}

func (mw *validationMiddleware) UpdateCAStatus(ctx context.Context, input *api.UpdateCAStatusInput) (*api.UpdateCAStatusOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.UpdateCAStatus(ctx, input)
}

func (mw *validationMiddleware) UpdateDeviceDigitalTwinReenrolmentStatus(ctx context.Context, input *api.UpdateDeviceDigitalTwinReenrolmentStatusInput) (*api.UpdateDeviceDigitalTwinReenrolmentStatusOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.UpdateDeviceDigitalTwinReenrolmentStatus(ctx, input)
}

func (mw *validationMiddleware) HandleForceReenrollEvent(ctx context.Context, input *api.HandleForceReenrollEventInput) (*api.HandleForceReenrollEventOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.HandleForceReenrollEvent(ctx, input)
}
