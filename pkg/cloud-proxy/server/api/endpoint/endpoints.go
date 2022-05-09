package endpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/service"
	cloudproviders "github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/cloud-providers"

	stdopentracing "github.com/opentracing/opentracing-go"
)

type Endpoints struct {
	HealthEndpoint                 endpoint.Endpoint
	GetCloudConnectorsEndpoint     endpoint.Endpoint
	GetDeviceConfigurationEndpoint endpoint.Endpoint
	SynchronizedCAEndpoint         endpoint.Endpoint
	UpdateSecurityAccessPolicy     endpoint.Endpoint
	UpdateDeviceCertStatusEndpoint endpoint.Endpoint
	EventHandlerEndpoint           endpoint.Endpoint
	UpdateCaStatusEndpoint         endpoint.Endpoint
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
	var updateCaStatusEndpoint endpoint.Endpoint
	{
		updateCaStatusEndpoint = MakeUpdateCaStatusEndpoint(s)
		updateCaStatusEndpoint = opentracing.TraceServer(otTracer, "UpdateCaStatusEndpoint")(updateDeviceCertStatusEndpoint)
	}
	var updateSecurityAccessPolicyEndpoint endpoint.Endpoint
	{
		updateSecurityAccessPolicyEndpoint = MakeUpdateSecurityAccessPolicyEndpoint(s)
		updateSecurityAccessPolicyEndpoint = opentracing.TraceServer(otTracer, "UpdateSecurityAccessPolicy")(updateSecurityAccessPolicyEndpoint)
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

	return Endpoints{
		HealthEndpoint:                 healthEndpoint,
		GetCloudConnectorsEndpoint:     getCloudConnectorsEndpoint,
		SynchronizedCAEndpoint:         synchronizedCAEndpoint,
		EventHandlerEndpoint:           eventHandlerEndpoint,
		UpdateSecurityAccessPolicy:     updateSecurityAccessPolicyEndpoint,
		UpdateDeviceCertStatusEndpoint: updateDeviceCertStatusEndpoint,
		GetDeviceConfigurationEndpoint: getDeviceConfigurationEndpoint,
		UpdateCaStatusEndpoint:         updateCaStatusEndpoint,
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
		connectors, err := s.GetCloudConnectors(ctx)
		return GetActiveCloudConnectorsResponse{CloudConnectors: connectors}, err
	}
}

func MakeGetDeviceConfigurationEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(GetDeviceConfigurationRequest)
		devicesConfig, err := s.GetDeviceConfiguration(ctx, req.ConnectorID, req.DeviceID)
		return devicesConfig, err
	}
}

func MakeSynchronizeCAEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(SynchronizeCARequest)
		connector, err := s.SynchronizeCA(ctx, req.ConnectorID, req.CAName, time.Now())
		return SynchronizedCAResponse{CloudConnector: connector}, err
	}
}

func MakeUpdateSecurityAccessPolicyEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(UpdateSecurityAccessPolicyRequest)
		connector, err := s.UpdateSecurityAccessPolicy(ctx, req.ConnectorID, req.Payload.CAName, req.Payload.AccessPolicy)
		return UpdateSecurityAccessPolicyResponse{CloudConnector: connector}, err
	}
}
func MakeUpdateDeviceStatusEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(UpdateDeviceCertStatusRequest)
		err = s.UpdateCertStatus(ctx, req.DeviceID, req.Payload.SerialNumber, req.Payload.Status, req.ConnectorID, req.Payload.CaName)
		return nil, err
	}
}
func MakeUpdateCaStatusEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(UpdateCaStatusRequest)
		err = s.UpdateCaStatus(ctx, req.CaName, req.Payload.Status)
		return nil, err
	}
}
func MakeEventHandlerEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		event := request.(cloudevents.Event)
		fmt.Println(event)
		switch event.Type() {
		case "io.lamassu.ca.create":

			var data LamassuCaCreateEvent
			json.Unmarshal(event.Data(), &data)
			err := s.HandleCreateCAEvent(ctx, data.CaName, data.SerialNumber, data.CaCert)
			return nil, err

		case "io.lamassu.ca.import":

			var data LamassuCaCreateEvent
			json.Unmarshal(event.Data(), &data)
			err := s.HandleCreateCAEvent(ctx, data.CaName, data.SerialNumber, data.CaCert)
			return nil, err

		case "io.lamassu.ca.update":

			var data LamassuCaUpdateStatusEvent
			json.Unmarshal(event.Data(), &data)
			err := s.HandleUpdateCaStatusEvent(ctx, data.CaName, data.Status)
			return nil, err

		case "io.lamassu.cert.update":

			var data LamassuCertUpdateStatusEvent
			json.Unmarshal(event.Data(), &data)
			err := s.HandleUpdateCertStatusEvent(ctx, data.CaName, data.SerialNumber, data.Status)
			return nil, err
		}
		return nil, nil
	}
}

type EmptyRequest struct{}

type SynchronizeCARequest struct {
	ConnectorID string `json:"connector_id"`
	CAName      string `json:"ca_name"`
}

type GetDeviceConfigurationRequest struct {
	ConnectorID string
	DeviceID    string
}

type SynchronizedCAResponse struct {
	CloudConnector cloudproviders.CloudConnector
}

type UpdateSecurityAccessPolicyRequest struct {
	ConnectorID string `json:"connector_id"`
	Payload     struct {
		CAName       string `json:"ca_name"`
		AccessPolicy string `json:"access_policy"`
	}
}
type UpdateDeviceCertStatusRequest struct {
	DeviceID    string `json:"device_id"`
	ConnectorID string `json:"connector_id"`
	Payload     struct {
		Status       string `json:"status"`
		SerialNumber string `json:"serial_number"`
		CaName       string `json:"ca_name"`
	}
}
type UpdateCaStatusRequest struct {
	CaName  string `json:"device_id"`
	Payload struct {
		Status string `json:"status"`
	}
}
type UpdateSecurityAccessPolicyResponse struct {
	CloudConnector cloudproviders.CloudConnector
}

type GetSynchronizedCAsByConnector struct {
	ConnectorID string
}

type GetSynchronizedCAsResponse struct {
	SynchronizeCAs []cloudproviders.SynchronizedCA
}

type HealthRequest struct{}

type HealthResponse struct {
	Healthy bool  `json:"healthy,omitempty"`
	Err     error `json:"err,omitempty"`
}

type GetActiveCloudConnectorsResponse struct {
	CloudConnectors []cloudproviders.CloudConnector
}

type GetDeviceConfigurationResponse struct {
	CloudConnectorDevices []interface{}
}

type AttachCAPolicyRequest struct {
	Policy      string `json:"policy"`
	ConnectorID string `json:"connector_id"`
}

type CreateCAResponse struct {
	status string
}
