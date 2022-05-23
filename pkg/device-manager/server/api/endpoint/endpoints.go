package endpoint

import (
	"context"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/service"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type Endpoints struct {
	HealthEndpoint              endpoint.Endpoint
	StatsEndpoint               endpoint.Endpoint
	PostDeviceEndpoint          endpoint.Endpoint
	GetDevices                  endpoint.Endpoint
	GetDeviceById               endpoint.Endpoint
	UpdateDeviceById            endpoint.Endpoint
	GetDevicesByDMS             endpoint.Endpoint
	DeleteDevice                endpoint.Endpoint
	DeleteRevoke                endpoint.Endpoint
	GetDeviceLogs               endpoint.Endpoint
	GetDeviceCert               endpoint.Endpoint
	GetDeviceCertHistory        endpoint.Endpoint
	GetDmsCertHistoryThirtyDays endpoint.Endpoint
	GetDmsLastIssueCert         endpoint.Endpoint
}

func MakeServerEndpoints(s service.Service, otTracer stdopentracing.Tracer) Endpoints {
	var healthEndpoint endpoint.Endpoint
	{
		healthEndpoint = MakeHealthEndpoint(s)
		healthEndpoint = opentracing.TraceServer(otTracer, "Health")(healthEndpoint)
	}
	var statsEndpoint endpoint.Endpoint
	{
		statsEndpoint = MakeStatsEndpoint(s)
		statsEndpoint = opentracing.TraceServer(otTracer, "Stats")(statsEndpoint)
	}
	var postDeviceEndpoint endpoint.Endpoint
	{
		postDeviceEndpoint = MakePostDeviceEndpoint(s)
		postDeviceEndpoint = opentracing.TraceServer(otTracer, "PostCSR")(postDeviceEndpoint)
	}
	var getDevicesEndpoint endpoint.Endpoint
	{
		getDevicesEndpoint = MakeGetDevicesEndpoint(s)
		getDevicesEndpoint = opentracing.TraceServer(otTracer, "GetDevices")(getDevicesEndpoint)
	}
	var getDevicesByIdEndpoint endpoint.Endpoint
	{
		getDevicesByIdEndpoint = MakeGetDeviceByIdEndpoint(s)
		getDevicesByIdEndpoint = opentracing.TraceServer(otTracer, "GetDeviceById")(getDevicesByIdEndpoint)
	}
	var updateDevicesByIdEndpoint endpoint.Endpoint
	{
		updateDevicesByIdEndpoint = MakeUpdateDeviceByIdEndpoint(s)
		updateDevicesByIdEndpoint = opentracing.TraceServer(otTracer, "UpdateDeviceById")(updateDevicesByIdEndpoint)
	}
	var getDevicesByDMSEndpoint endpoint.Endpoint
	{
		getDevicesByDMSEndpoint = MakeGetDevicesByDMSEndpoint(s)
		getDevicesByDMSEndpoint = opentracing.TraceServer(otTracer, "GetDevicesByDMS")(getDevicesByDMSEndpoint)
	}
	var deleteDeviceEndpoint endpoint.Endpoint
	{
		deleteDeviceEndpoint = MakeDeleteDeviceEndpoint(s)
		deleteDeviceEndpoint = opentracing.TraceServer(otTracer, "DeleteDevice")(deleteDeviceEndpoint)
	}
	var deleteRevokeEndpoint endpoint.Endpoint
	{
		deleteRevokeEndpoint = MakeDeleteRevokeEndpoint(s)
		deleteRevokeEndpoint = opentracing.TraceServer(otTracer, "deleteRevokeEndpoint")(deleteRevokeEndpoint)
	}
	var getDeviceLogsEndpoint endpoint.Endpoint
	{
		getDeviceLogsEndpoint = MakeGetDeviceLogsEndpoint(s)
		getDeviceLogsEndpoint = opentracing.TraceServer(otTracer, "getDeviceLogsEndpoint")(getDeviceLogsEndpoint)
	}
	var getDeviceCertEndpoint endpoint.Endpoint
	{
		getDeviceCertEndpoint = MakeGetDeviceCertEndpoint(s)
		getDeviceCertEndpoint = opentracing.TraceServer(otTracer, "getDeviceCertEndpoint")(getDeviceCertEndpoint)
	}
	var getDeviceCertHistoryEndpoint endpoint.Endpoint
	{
		getDeviceCertHistoryEndpoint = MakeGetDeviceCertHistoryEndpoint(s)
		getDeviceCertHistoryEndpoint = opentracing.TraceServer(otTracer, "getDeviceCertHistoryEndpoint")(getDeviceCertHistoryEndpoint)
	}
	var getDmsCertHistoryThirtyDaysEndpoint endpoint.Endpoint
	{
		getDmsCertHistoryThirtyDaysEndpoint = MakeGetDmsCertHistoryThirtyDaysEndpoint(s)
		getDmsCertHistoryThirtyDaysEndpoint = opentracing.TraceServer(otTracer, "getDmsCertHistoryThirtyDaysEndpoint")(getDmsCertHistoryThirtyDaysEndpoint)
	}
	var getDmsLastIssueCertEndpoint endpoint.Endpoint
	{
		getDmsLastIssueCertEndpoint = MakeGetDmsLastIssueCertEndpoint(s)
		getDmsLastIssueCertEndpoint = opentracing.TraceServer(otTracer, "getDmsLastIssueCertEndpoint")(getDmsLastIssueCertEndpoint)
	}

	return Endpoints{
		HealthEndpoint:              healthEndpoint,
		StatsEndpoint:               statsEndpoint,
		PostDeviceEndpoint:          postDeviceEndpoint,
		GetDevices:                  getDevicesEndpoint,
		GetDeviceById:               getDevicesByIdEndpoint,
		UpdateDeviceById:            updateDevicesByIdEndpoint,
		GetDevicesByDMS:             getDevicesByDMSEndpoint,
		DeleteDevice:                deleteDeviceEndpoint,
		DeleteRevoke:                deleteRevokeEndpoint,
		GetDeviceLogs:               getDeviceLogsEndpoint,
		GetDeviceCert:               getDeviceCertEndpoint,
		GetDeviceCertHistory:        getDeviceCertHistoryEndpoint,
		GetDmsCertHistoryThirtyDays: getDmsCertHistoryThirtyDaysEndpoint,
		GetDmsLastIssueCert:         getDmsLastIssueCertEndpoint,
	}
}

func MakeHealthEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		healthy := s.Health(ctx)
		return HealthResponse{Healthy: healthy}, nil
	}
}

func MakeStatsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		stats, scanDate := s.Stats(ctx)
		return StatsResponse{Stats: stats, ScanDate: scanDate}, nil
	}
}

func MakePostDeviceEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(dto.CreateDeviceRequest)
		/*err = ValidateCreatrCARequest(req)
		if err != nil {
			valError := devmanagererrors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}*/
		device, e := s.PostDevice(ctx, req.Alias, req.DeviceID, req.DmsId, req.Description, req.Tags, req.IconName, req.IconColor)
		return device, e
	}
}

func MakeGetDevicesEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(dto.QueryParameters)
		devices, length, e := s.GetDevices(ctx, req)
		return dto.GetDevicesResponse{TotalDevices: length, Devices: devices}, e
	}
}

func MakeGetDeviceByIdEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(GetDevicesByIdRequest)
		device, e := s.GetDeviceById(ctx, req.Id)
		return device, e
	}
}

func MakeUpdateDeviceByIdEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(dto.UpdateDevicesByIdRequest)
		device, e := s.UpdateDeviceById(ctx, req.Alias, req.DeviceID, req.DmsId, req.Description, req.Tags, req.IconName, req.IconColor)
		return device, e
	}
}

func MakeGetDevicesByDMSEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(GetDevicesByDMSRequest)
		devices, e := s.GetDevicesByDMS(ctx, req.Id, req.QueryParameters)
		return dto.GetDevicesResponse{TotalDevices: len(devices), Devices: devices}, e
	}
}
func MakeDeleteDeviceEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(DeleteDeviceRequest)
		e := s.DeleteDevice(ctx, req.Id)
		if e != nil {
			return "", e
		} else {
			return "OK", e
		}
	}
}
func MakeDeleteRevokeEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(DeleteRevokeRequest)
		e := s.RevokeDeviceCert(ctx, req.Id, "Manual revocation")
		return nil, e
	}
}

func MakeGetDeviceLogsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		reqL := request.(GetDeviceLogsRequest)
		logs, e := s.GetDeviceLogs(ctx, reqL.Id)
		return logs, e
	}
}

func MakeGetDeviceCertEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(GetDeviceCertRequest)
		deviceCert, e := s.GetDeviceCert(ctx, req.Id)
		return deviceCert, e
	}
}
func MakeGetDeviceCertHistoryEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		reqCHR := request.(GetDeviceCertHistoryRequest)
		history, e := s.GetDeviceCertHistory(ctx, reqCHR.Id)
		return history, e
	}
}
func MakeGetDmsCertHistoryThirtyDaysEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		var req dto.QueryParameters
		history, e := s.GetDmsCertHistoryThirtyDays(ctx, req)
		return history, e
	}
}
func MakeGetDmsLastIssueCertEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(dto.QueryParameters)
		history, e := s.GetDmsLastIssuedCert(ctx, req)
		return history, e
	}
}

type HealthRequest struct{}

type HealthResponse struct {
	Healthy bool  `json:"healthy,omitempty"`
	Err     error `json:"err,omitempty"`
}

type StatsRequest struct{}

type StatsResponse struct {
	Stats    dto.Stats `json:"stats"`
	ScanDate time.Time `json:"scan_date"`
}

type PostDeviceResponse struct {
	Device dto.Device `json:"device,omitempty"`
	Err    error      `json:"err,omitempty"`
}

func (r PostDeviceResponse) error() error { return r.Err }

type GetDevicesByIdRequest struct {
	Id string
}

type GetDevicesByDMSRequest struct {
	Id              string
	QueryParameters dto.QueryParameters
}
type DeleteDeviceRequest struct {
	Id string
}
type PostIssueCertResponse struct {
	Crt string `json:"crt,omitempty"`
	Err error  `json:"err,omitempty"`
}
type PostIssueCertUsingDefaultResponse struct {
	Crt     string `json:"crt,omitempty"`
	PrivKey string `json:"priv_key,omitempty"`
	Err     error  `json:"err,omitempty"`
}
type DeleteRevokeRequest struct {
	Id string
}
type GetDeviceLogsRequest struct {
	Id string
}
type GetDeviceCertRequest struct {
	Id string
}
type GetDeviceCertHistoryRequest struct {
	Id string
}
