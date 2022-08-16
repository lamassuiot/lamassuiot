package endpoint

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/service"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type Endpoints struct {
	HealthEndpoint                  endpoint.Endpoint
	GetStatsEndpoint                endpoint.Endpoint
	CreateDeviceEndpoint            endpoint.Endpoint
	UpdateDeviceMetadataEndpoint    endpoint.Endpoint
	DecommisionDeviceEndpoint       endpoint.Endpoint
	GetDevicesEndpoint              endpoint.Endpoint
	GetDeviceByIdEndpoint           endpoint.Endpoint
	RevokeActiveCertificateEndpoint endpoint.Endpoint
	GetDeviceLogsEndpoint           endpoint.Endpoint
}

func MakeServerEndpoints(s service.Service, otTracer stdopentracing.Tracer) Endpoints {
	var healthEndpoint endpoint.Endpoint
	{
		healthEndpoint = MakeHealthEndpoint(s)
		healthEndpoint = opentracing.TraceServer(otTracer, "Health")(healthEndpoint)
	}
	var getStatsEndpoint endpoint.Endpoint
	{
		getStatsEndpoint = MakeGetStatsEndpoint(s)
		getStatsEndpoint = opentracing.TraceServer(otTracer, "GetStats")(getStatsEndpoint)
	}
	var createDeviceEndpoint endpoint.Endpoint
	{
		createDeviceEndpoint = MakeCreateDeviceEndpoint(s)
		createDeviceEndpoint = opentracing.TraceServer(otTracer, "CreateDevice")(createDeviceEndpoint)
	}
	var updateDeviceMetadataEndpoint endpoint.Endpoint
	{
		updateDeviceMetadataEndpoint = MakeUpdateDeviceMetadataEndpoint(s)
		updateDeviceMetadataEndpoint = opentracing.TraceServer(otTracer, "UpdateDeviceMetadata")(updateDeviceMetadataEndpoint)
	}
	var decommisionDeviceEndpoint endpoint.Endpoint
	{
		decommisionDeviceEndpoint = MakeDecommisionDeviceEndpoint(s)
		decommisionDeviceEndpoint = opentracing.TraceServer(otTracer, "DecommisionDevice")(decommisionDeviceEndpoint)
	}
	var getDevicesEndpoint endpoint.Endpoint
	{
		getDevicesEndpoint = MakeGetDevicesEndpoint(s)
		getDevicesEndpoint = opentracing.TraceServer(otTracer, "GetDevices")(getDevicesEndpoint)
	}
	var getDeviceByIdEndpoint endpoint.Endpoint
	{
		getDeviceByIdEndpoint = MakeGetDeviceByIdEndpoint(s)
		getDeviceByIdEndpoint = opentracing.TraceServer(otTracer, "GetDeviceById")(getDeviceByIdEndpoint)
	}
	var revokeActiveCertificateEndpoint endpoint.Endpoint
	{
		revokeActiveCertificateEndpoint = MakeRevokeActiveCertificateEndpoint(s)
		revokeActiveCertificateEndpoint = opentracing.TraceServer(otTracer, "RevokeActiveCertificate")(revokeActiveCertificateEndpoint)
	}
	var getDeviceLogsEndpoint endpoint.Endpoint
	{
		getDeviceLogsEndpoint = MakeGetDeviceLogsEndpoint(s)
		getDeviceLogsEndpoint = opentracing.TraceServer(otTracer, "GetDeviceLogs")(getDeviceLogsEndpoint)
	}

	return Endpoints{
		HealthEndpoint:                  healthEndpoint,
		GetStatsEndpoint:                getStatsEndpoint,
		CreateDeviceEndpoint:            createDeviceEndpoint,
		UpdateDeviceMetadataEndpoint:    updateDeviceMetadataEndpoint,
		DecommisionDeviceEndpoint:       decommisionDeviceEndpoint,
		GetDevicesEndpoint:              getDevicesEndpoint,
		GetDeviceByIdEndpoint:           getDeviceByIdEndpoint,
		RevokeActiveCertificateEndpoint: revokeActiveCertificateEndpoint,
		GetDeviceLogsEndpoint:           getDeviceLogsEndpoint,
	}
}

func MakeHealthEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		output := s.Health(ctx)
		return HealthResponse{Healthy: output}, nil
	}
}

func ValidateGetStatsRequest(request api.GetStatsInput) error {
	GetStatsInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetStatsInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(GetStatsInputStructLevelValidation, api.GetStatsInput{})
	return validate.Struct(request)
}
func MakeGetStatsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetStatsInput)

		err = ValidateGetStatsRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.GetStats(ctx, &input)
		return output, err
	}
}

func ValidateCreateDeviceRequest(request api.CreateDeviceInput) error {
	CreateDeviceInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.CreateDeviceInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(CreateDeviceInputStructLevelValidation, api.CreateDeviceInput{})
	return validate.Struct(request)
}
func MakeCreateDeviceEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.CreateDeviceInput)

		err = ValidateCreateDeviceRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.CreateDevice(ctx, &input)
		return output, err
	}
}

func ValidateUpdateDeviceMetadataRequest(request api.UpdateDeviceMetadataInput) error {
	UpdateDeviceMetadataInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.UpdateDeviceMetadataInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(UpdateDeviceMetadataInputStructLevelValidation, api.UpdateDeviceMetadataInput{})
	return validate.Struct(request)
}
func MakeUpdateDeviceMetadataEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.UpdateDeviceMetadataInput)

		err = ValidateUpdateDeviceMetadataRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.UpdateDeviceMetadata(ctx, &input)
		return output, err
	}
}

func ValidateDecommisionDeviceRequest(request api.DecommisionDeviceInput) error {
	DecommisionDeviceInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.DecommisionDeviceInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(DecommisionDeviceInputStructLevelValidation, api.DecommisionDeviceInput{})
	return validate.Struct(request)
}
func MakeDecommisionDeviceEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.DecommisionDeviceInput)

		err = ValidateDecommisionDeviceRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.DecommisionDevice(ctx, &input)
		return output, err
	}
}

func ValidateGetDevicesRequest(request api.GetDevicesInput) error {
	GetDevicesInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetDevicesInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(GetDevicesInputStructLevelValidation, api.GetDevicesInput{})
	return validate.Struct(request)
}
func MakeGetDevicesEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetDevicesInput)

		err = ValidateGetDevicesRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.GetDevices(ctx, &input)
		return output, err
	}
}

func ValidateGetDeviceByIdRequest(request api.GetDeviceByIdInput) error {
	GetDeviceByIdInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetDeviceByIdInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(GetDeviceByIdInputStructLevelValidation, api.GetDeviceByIdInput{})
	return validate.Struct(request)
}
func MakeGetDeviceByIdEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetDeviceByIdInput)

		err = ValidateGetDeviceByIdRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.GetDeviceById(ctx, &input)
		return output, err
	}
}

func ValidateRevokeActiveCertificateRequest(request api.RevokeActiveCertificateInput) error {
	RevokeActiveCertificateInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.RevokeActiveCertificateInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(RevokeActiveCertificateInputStructLevelValidation, api.RevokeActiveCertificateInput{})
	return validate.Struct(request)
}
func MakeRevokeActiveCertificateEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.RevokeActiveCertificateInput)

		err = ValidateRevokeActiveCertificateRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.RevokeActiveCertificate(ctx, &input)
		return output, err
	}
}

func ValidateGetDeviceLogsRequest(request api.GetDeviceLogsInput) error {
	GetDeviceLogsInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetDeviceLogsInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(GetDeviceLogsInputStructLevelValidation, api.GetDeviceLogsInput{})
	return validate.Struct(request)
}
func MakeGetDeviceLogsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetDeviceLogsInput)

		err = ValidateGetDeviceLogsRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.GetDeviceLogs(ctx, &input)
		return output, err
	}
}

type HealthResponse struct {
	Healthy bool  `json:"healthy,omitempty"`
	Err     error `json:"err,omitempty"`
}
