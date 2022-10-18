package endpoint

import (
	"context"
	"encoding/json"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/tracing/opentracing"
	caApi "github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/service"
	devApi "github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"

	stdopentracing "github.com/opentracing/opentracing-go"
)

type Endpoints struct {
	HealthEndpoint                                   endpoint.Endpoint
	GetCloudConnectorsEndpoint                       endpoint.Endpoint
	GetDeviceConfigurationEndpoint                   endpoint.Endpoint
	SynchronizedCAEndpoint                           endpoint.Endpoint
	UpdateConnectorConfigurationEndpoint             endpoint.Endpoint
	UpdateDeviceCertStatusEndpoint                   endpoint.Endpoint
	EventHandlerEndpoint                             endpoint.Endpoint
	UpdateCAStatusEndpoint                           endpoint.Endpoint
	UpdateDeviceDigitalTwinReenrolmentStatusEndpoint endpoint.Endpoint
}

func MakeServerEndpoints(s service.Service, otTracer stdopentracing.Tracer) Endpoints {
	var healthEndpoint endpoint.Endpoint
	{
		healthEndpoint = MakeHealthEndpoint(s)
		healthEndpoint = opentracing.TraceServer(otTracer, "Health")(healthEndpoint)
	}
	var getCloudConnectorsEndpoint endpoint.Endpoint
	{
		getCloudConnectorsEndpoint = MakeGetCloudConnectorsEndpoint(s)
		getCloudConnectorsEndpoint = opentracing.TraceServer(otTracer, "GetCloudConnectorsEndpoint")(getCloudConnectorsEndpoint)
	}

	var synchronizedCAEndpoint endpoint.Endpoint
	{
		synchronizedCAEndpoint = MakeSynchronizeCAEndpoint(s)
		synchronizedCAEndpoint = opentracing.TraceServer(otTracer, "SynchronizedCAEndpoint")(synchronizedCAEndpoint)
	}
	var updateDeviceCertStatusEndpoint endpoint.Endpoint
	{
		updateDeviceCertStatusEndpoint = MakeUpdateDeviceStatusEndpoint(s)
		updateDeviceCertStatusEndpoint = opentracing.TraceServer(otTracer, "UpdateDeviceCertStatusEndpoint")(updateDeviceCertStatusEndpoint)
	}
	var updateCAStatusEndpoint endpoint.Endpoint
	{
		updateCAStatusEndpoint = MakeUpdateCAStatusEndpoint(s)
		updateCAStatusEndpoint = opentracing.TraceServer(otTracer, "UpdateCAStatusEndpoint")(updateCAStatusEndpoint)
	}
	var updateConnectorConfigurationEndpoint endpoint.Endpoint
	{
		updateConnectorConfigurationEndpoint = MakeUpdateConnectorConfigurationEndpoint(s)
		updateConnectorConfigurationEndpoint = opentracing.TraceServer(otTracer, "UpdateConnectorConfigurationEndpoint")(updateConnectorConfigurationEndpoint)
	}
	var eventHandlerEndpoint endpoint.Endpoint
	{
		eventHandlerEndpoint = MakeEventHandlerEndpoint(s)
		eventHandlerEndpoint = opentracing.TraceServer(otTracer, "EventHandlerEndpoint")(eventHandlerEndpoint)
	}
	var getDeviceConfigurationEndpoint endpoint.Endpoint
	{
		getDeviceConfigurationEndpoint = MakeGetDeviceConfigurationEndpoint(s)
		getDeviceConfigurationEndpoint = opentracing.TraceServer(otTracer, "GetDeviceConfigurationEndpoint")(getDeviceConfigurationEndpoint)
	}
	var updateDeviceDigitalTwinReenrolmentStatusEndpoint endpoint.Endpoint
	{
		updateDeviceDigitalTwinReenrolmentStatusEndpoint = MakeUpdateDeviceDigitalTwinReenrolmentStatusEndpoint(s)
		updateDeviceDigitalTwinReenrolmentStatusEndpoint = opentracing.TraceServer(otTracer, "UpdateDeviceDigitalTwinReenrolmentStatusEndpoint")(updateDeviceDigitalTwinReenrolmentStatusEndpoint)
	}

	return Endpoints{
		HealthEndpoint:                       healthEndpoint,
		GetCloudConnectorsEndpoint:           getCloudConnectorsEndpoint,
		SynchronizedCAEndpoint:               synchronizedCAEndpoint,
		EventHandlerEndpoint:                 eventHandlerEndpoint,
		UpdateConnectorConfigurationEndpoint: updateConnectorConfigurationEndpoint,
		UpdateDeviceCertStatusEndpoint:       updateDeviceCertStatusEndpoint,
		GetDeviceConfigurationEndpoint:       getDeviceConfigurationEndpoint,
		UpdateCAStatusEndpoint:               updateCAStatusEndpoint,
	}
}
func MakeHealthEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		healthy := s.Health(ctx)
		return HealthResponse{Healthy: healthy}, nil
	}
}

func MakeGetCloudConnectorsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetCloudConnectorsInput)
		output, err := s.GetCloudConnectors(ctx, &input)
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

func MakeSynchronizeCAEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.SynchronizeCAInput)
		output, err := s.SynchronizeCA(ctx, &input)
		return output, err
	}
}

func MakeUpdateConnectorConfigurationEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.UpdateCloudProviderConfigurationInput)
		output, err := s.UpdateCloudProviderConfiguration(ctx, &input)
		return output, err
	}
}

func MakeUpdateDeviceStatusEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.UpdateDeviceCertificateStatusInput)
		output, err := s.UpdateDeviceCertificateStatus(ctx, &input)
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
func MakeUpdateDeviceDigitalTwinReenrolmentStatusEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.UpdateDeviceDigitalTwinReenrolmentStatusInput)
		output, err := s.UpdateDeviceDigitalTwinReenrolmentStatus(ctx, &input)
		return output, err
	}
}

func MakeEventHandlerEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		event := request.(cloudevents.Event)
		switch event.Type() {
		case "io.lamassuiot.ca.create":
			var data caApi.CreateCAOutputSerialized
			json.Unmarshal(event.Data(), &data)
			_, err := s.HandleCreateCAEvent(ctx, &api.HandleCreateCAEventInput{
				CACertificate: data.CACertificateSerialized.Deserialize(),
			})
			return nil, err

		// case "io.lamassu.ca.import":

		// 	var data LamassuCaCreateEvent
		// 	json.Unmarshal(event.Data(), &data)
		// 	err := s.HandleCreateCAEvent(ctx, data.CaName, data.SerialNumber, data.CaCert)
		// 	return nil, err

		case "io.lamassuiot.ca.update":
			var data caApi.UpdateCAStatusOutputSerialized
			json.Unmarshal(event.Data(), &data)
			_, err := s.HandleUpdateCAStatusEvent(ctx, &api.HandleUpdateCAStatusEventInput{
				CACertificate: data.CACertificateSerialized.Deserialize(),
			})
			return nil, err

		case "io.lamassuiot.certificate.update":
			var data caApi.UpdateCertificateStatusOutputSerialized
			json.Unmarshal(event.Data(), &data)
			_, err := s.HandleUpdateCertificateStatusEvent(ctx, &api.HandleUpdateCertificateStatusEventInput{
				Certificate: data.CertificateSerialized.Deserialize(),
			})
			return nil, err
		case "io.lamassuiot.device.forceReenroll":
			var data devApi.ForceReenrollOutputSerialized
			json.Unmarshal(event.Data(), &data)
			_, err := s.HandleForceReenrollEvent(ctx, &api.HandleForceReenrollEventInput{
				DeviceID:      data.Deserialize().DeviceID,
				SlotID:        data.Deserialize().SlotID,
				ForceReenroll: data.Deserialize().ForceReenroll,
				Crt:           data.Deserialize().Crt,
			})
			return nil, err
		case "io.lamassuiot.device.reenroll":
			var data devApi.ForceReenrollOutputSerialized
			json.Unmarshal(event.Data(), &data)
			_, err := s.HandleForceReenrollEvent(ctx, &api.HandleForceReenrollEventInput{
				DeviceID:      data.Deserialize().DeviceID,
				SlotID:        data.Deserialize().SlotID,
				ForceReenroll: data.Deserialize().ForceReenroll,
				Crt:           data.Deserialize().Crt,
			})
			return nil, err
		}
		return nil, nil
	}
}

type HealthRequest struct{}

type HealthResponse struct {
	Healthy bool `json:"healthy"`
}
