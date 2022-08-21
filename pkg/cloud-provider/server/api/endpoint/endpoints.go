package endpoint

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-provider/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-provider/server/api/service"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type Endpoints struct {
	RegisterCAEndpoint                    endpoint.Endpoint
	UpdateConfigurationEndpoint           endpoint.Endpoint
	GetConfigurationEndpoint              endpoint.Endpoint
	GetDeviceConfigurationEndpoint        endpoint.Endpoint
	UpdateCAStatusEndpoint                endpoint.Endpoint
	UpdateDeviceCertificateStatusEndpoint endpoint.Endpoint
}

func MakeServerEndpoints(s service.Service, otTracer stdopentracing.Tracer) Endpoints {
	registerCAEndpoint := MakeRegisterCAEndpoint(s)
	updateConfigurationEndpoint := MakeUpdateConfigurationEndpoint(s)
	getConfigurationEndpoint := MakeGetConfigurationEndpoint(s)
	getDeviceConfigurationEndpoint := MakeGetDeviceConfigurationEndpoint(s)
	updateCAStatusEndpoint := MakeUpdateCAStatusEndpoint(s)
	updateDeviceCertificateStatusEndpoint := MakeUpdateDeviceCertificateStatusEndpoint(s)

	return Endpoints{
		RegisterCAEndpoint:                    registerCAEndpoint,
		UpdateConfigurationEndpoint:           updateConfigurationEndpoint,
		GetConfigurationEndpoint:              getConfigurationEndpoint,
		GetDeviceConfigurationEndpoint:        getDeviceConfigurationEndpoint,
		UpdateCAStatusEndpoint:                updateCAStatusEndpoint,
		UpdateDeviceCertificateStatusEndpoint: updateDeviceCertificateStatusEndpoint,
	}
}

func MakeRegisterCAEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.RegisterCAInput)
		output, err := s.RegisterCA(ctx, &input)
		return output, err
	}
}

func MakeUpdateConfigurationEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.UpdateConfigurationInput)
		output, err := s.UpdateConfiguration(ctx, &input)
		return output, err
	}
}

func MakeGetConfigurationEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetConfigurationInput)
		output, err := s.GetConfiguration(ctx, &input)
		return output, err
	}
}

func MakeGetDeviceConfigurationEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetDeviceConfigurationInput)
		output, err := s.GetDeviceConfiguration(ctx, &input)
		return output, err
	}
}

func MakeUpdateCAStatusEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.UpdateCAStatusInput)
		output, err := s.UpdateCAStatus(ctx, &input)
		return output, err
	}
}

func MakeUpdateDeviceCertificateStatusEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.UpdateDeviceCertificateStatusInput)
		output, err := s.UpdateDeviceCertificateStatus(ctx, &input)
		return output, err
	}
}
