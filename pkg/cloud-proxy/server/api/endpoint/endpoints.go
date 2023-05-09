package endpoint

import (
	"context"
	"encoding/json"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-kit/kit/endpoint"
	caApi "github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/service"
	devApi "github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"
	dmsApi "github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
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

func MakeServerEndpoints(s service.Service) Endpoints {
	var healthEndpoint = MakeHealthEndpoint(s)
	var getCloudConnectorsEndpoint = MakeGetCloudConnectorsEndpoint(s)
	var synchronizedCAEndpoint = MakeSynchronizeCAEndpoint(s)
	var updateDeviceCertStatusEndpoint = MakeUpdateDeviceStatusEndpoint(s)
	var updateCAStatusEndpoint = MakeUpdateCAStatusEndpoint(s)
	var updateConnectorConfigurationEndpoint = MakeUpdateConnectorConfigurationEndpoint(s)
	var eventHandlerEndpoint = MakeEventHandlerEndpoint(s)
	var getDeviceConfigurationEndpoint = MakeGetDeviceConfigurationEndpoint(s)
	var updateDeviceDigitalTwinReenrolmentStatusEndpoint = MakeUpdateDeviceDigitalTwinReenrolmentStatusEndpoint(s)

	return Endpoints{
		HealthEndpoint:                                   healthEndpoint,
		GetCloudConnectorsEndpoint:                       getCloudConnectorsEndpoint,
		SynchronizedCAEndpoint:                           synchronizedCAEndpoint,
		EventHandlerEndpoint:                             eventHandlerEndpoint,
		UpdateConnectorConfigurationEndpoint:             updateConnectorConfigurationEndpoint,
		UpdateDeviceCertStatusEndpoint:                   updateDeviceCertStatusEndpoint,
		GetDeviceConfigurationEndpoint:                   getDeviceConfigurationEndpoint,
		UpdateCAStatusEndpoint:                           updateCAStatusEndpoint,
		UpdateDeviceDigitalTwinReenrolmentStatusEndpoint: updateDeviceDigitalTwinReenrolmentStatusEndpoint,
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

		case "io.lamassuiot.dms.update":
			var data dmsApi.DeviceManufacturingServiceSerialized
			json.Unmarshal(event.Data(), &data)
			_, err := s.HandleUpdateDMSCaCerts(ctx, &api.HandleUpdateDMSCaCertsInput{
				DeviceManufacturingService: data.Deserialize(),
			})
			return nil, err

		case "io.lamassuiot.dms.update-authorizedcas":
			var data dmsApi.DeviceManufacturingServiceSerialized
			json.Unmarshal(event.Data(), &data)
			_, err := s.HandleUpdateDMSCaCerts(ctx, &api.HandleUpdateDMSCaCertsInput{
				DeviceManufacturingService: data.Deserialize(),
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
