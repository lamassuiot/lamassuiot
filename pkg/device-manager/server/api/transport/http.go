package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/endpoint"
	devmanagererrors "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type errorer interface {
	error() error
}

func ErrMissingDevID() error {
	return &devmanagererrors.GenericError{
		Message:    "Device ID not specified",
		StatusCode: 400,
	}
}
func HTTPToContext(logger log.Logger) httptransport.RequestFunc {
	return func(ctx context.Context, req *http.Request) context.Context {
		// Try to join to a trace propagated in `req`.
		logger := log.With(logger, "span_id", stdopentracing.SpanFromContext(ctx))
		return context.WithValue(ctx, utils.LamassuLoggerContextKey, logger)
	}
}

func MakeHTTPHandler(s service.Service, logger log.Logger, otTracer stdopentracing.Tracer) http.Handler {
	r := mux.NewRouter()
	e := endpoint.MakeServerEndpoints(s, otTracer)
	options := []httptransport.ServerOption{
		httptransport.ServerBefore(HTTPToContext(logger)),
		httptransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		httptransport.ServerErrorEncoder(encodeError),
	}
	r.Methods("GET").Path("/v1/health").Handler(httptransport.NewServer(
		e.HealthEndpoint,
		decodeHealthRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "Health", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))
	r.Methods("GET").Path("/v1/stats").Handler(httptransport.NewServer(
		e.StatsEndpoint,
		decodeStatsRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "Stats", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("POST").Path("/v1/devices").Handler(httptransport.NewServer(
		e.PostDeviceEndpoint,
		decodePostDeviceRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "PostDevice", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/v1/devices").Handler(httptransport.NewServer(
		e.GetDevices,
		decodeRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetDevices", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/v1/devices/{deviceId}").Handler(httptransport.NewServer(
		e.GetDeviceById,
		decodeGetDeviceById,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetDeviceById", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("PUT").Path("/v1/devices/{deviceId}").Handler(httptransport.NewServer(
		e.UpdateDeviceById,
		decodeUpdateDeviceById,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "UpdateDevicesById", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/v1/devices/dms/{dmsId}").Handler(httptransport.NewServer(
		e.GetDevicesByDMS,
		decodeGetDevicesByDMSRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetDevicesByDMS", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("DELETE").Path("/v1/devices/{deviceId}").Handler(httptransport.NewServer(
		e.DeleteDevice,
		decodeDeleteDeviceRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "DeleteDevice", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("DELETE").Path("/v1/devices/{deviceId}/revoke").Handler(httptransport.NewServer(
		e.DeleteRevoke,
		decodedecodeDeleteRevokeRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "DeleteRevoke", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/v1/devices/{deviceId}/logs").Handler(httptransport.NewServer(
		e.GetDeviceLogs,
		decodedecodeGetDeviceLogsRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetDeviceLogs", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/v1/devices/{deviceId}/cert").Handler(httptransport.NewServer(
		e.GetDeviceCert,
		decodedecodeGetDeviceCertRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetDeviceCert", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/v1/devices/{deviceId}/cert-history").Handler(httptransport.NewServer(
		e.GetDeviceCertHistory,
		decodedecodeGetDeviceCertHistoryRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetDeviceCertHistory", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/v1/devices/dms-cert-history/thirty-days").Handler(httptransport.NewServer(
		e.GetDmsCertHistoryThirtyDays,
		decodedecodeGetDmsCertHistoryThirtyDaysRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetDmsCertHistoryThirtyDays", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/v1/devices/dms-cert-history/last-issued").Handler(httptransport.NewServer(
		e.GetDmsLastIssueCert,
		decodedecodeGetDmsLastIssueCert,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetDmsLastIssueCert", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	return r
}

func decodeHealthRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var req endpoint.HealthRequest
	return req, nil
}

func decodeStatsRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var req endpoint.HealthRequest
	return req, nil
}

func decodeRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {

	return filterQuery(r), nil
}

func filterQuery(r *http.Request) dto.QueryParameters {
	f := ""
	orderArray := ""
	pageArray := ""
	page := ""
	offset := ""
	field := ""
	order := ""

	helper := r.URL.RawQuery

	if len(r.URL.RawQuery) > 0 {

		f, helper = middle(helper, "filter={")

		orderArray, helper = middle(helper, "s={")
		if orderArray != "" {
			s := strings.Split(orderArray, ",")
			order = s[0]
			field = s[1]
		}

		pageArray, helper = middle(helper, "page={")
		if pageArray != "" {
			s := strings.Split(pageArray, ",")
			page = s[0]
			offset = s[1]
		}

	}

	pageInt, _ := strconv.Atoi(page)
	offsetInt, _ := strconv.Atoi(offset)
	pagination := dto.PaginationOptions{
		Page:   pageInt,
		Offset: offsetInt,
	}
	orderOpt := dto.OrderOptions{
		Order: order,
		Field: field,
	}
	query := dto.QueryParameters{
		Order:      orderOpt,
		Pagination: pagination,
		Filter:     f,
	}
	return query
}

func removeAmpersand(helper string) string {
	if strings.HasPrefix(helper, "&") {
		helper = strings.TrimPrefix(helper, "&")
	}
	return helper
}

func decodePostDeviceRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var createDeviceRequest dto.CreateDeviceRequest
	json.NewDecoder(r.Body).Decode((&createDeviceRequest))
	if err != nil {
		return nil, errors.New("cannot decode JSON request")
	}
	return createDeviceRequest, nil
}

func decodeGetDeviceById(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	id, ok := vars["deviceId"]
	if !ok {
		return nil, ErrMissingDevID()
	}
	return endpoint.GetDevicesByIdRequest{Id: id}, nil
}

func decodeUpdateDeviceById(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var updateDeviceRequest dto.UpdateDevicesByIdRequest
	json.NewDecoder(r.Body).Decode((&updateDeviceRequest))
	if err != nil {
		return nil, errors.New("cannot decode JSON request")
	}
	return updateDeviceRequest, nil
}

func decodeGetDevicesByDMSRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	id, ok := vars["dmsId"]
	if !ok {
		return nil, ErrMissingDevID()
	}
	return endpoint.GetDevicesByDMSRequest{Id: id, QueryParameters: filterQuery(r)}, nil
}

func decodeDeleteDeviceRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	id, ok := vars["deviceId"]
	if !ok {
		return nil, ErrMissingDevID()
	}
	return endpoint.DeleteDeviceRequest{Id: id}, nil
}
func decodedecodeDeleteRevokeRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	id, ok := vars["deviceId"]
	if !ok {
		return nil, ErrMissingDevID()
	}
	return endpoint.DeleteRevokeRequest{Id: id}, nil
}
func decodedecodeGetDeviceLogsRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	id, ok := vars["deviceId"]
	if !ok {
		return nil, ErrMissingDevID()
	}

	return endpoint.GetDeviceLogsRequest{Id: id}, nil
}
func decodedecodeGetDeviceCertRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	id, ok := vars["deviceId"]
	if !ok {
		return nil, ErrMissingDevID()
	}
	return endpoint.GetDeviceCertRequest{Id: id}, nil
}
func decodedecodeGetDeviceCertHistoryRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	id, ok := vars["deviceId"]
	if !ok {
		return nil, ErrMissingDevID()
	}
	return endpoint.GetDeviceCertHistoryRequest{Id: id}, nil
}
func decodedecodeGetDmsCertHistoryThirtyDaysRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	//var req endpoint.HealthRequest
	return decodeRequest(ctx, r)
}
func decodedecodeGetDmsLastIssueCert(ctx context.Context, r *http.Request) (request interface{}, err error) {
	//var req endpoint.HealthRequest
	return decodeRequest(ctx, r)

}

func encodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		// Not a Go kit transport error, but a business-logic error.
		// Provide those as HTTP errors.
		encodeError(ctx, e.error(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	if err == nil {
		panic("encodeError with nil error")
	}
	http.Error(w, err.Error(), codeFrom(err))
}

func codeFrom(err error) int {
	switch e := err.(type) {
	case *devmanagererrors.ValidationError:
		return http.StatusBadRequest
	case *devmanagererrors.ResourceNotFoundError:
		return http.StatusNotFound
	case *devmanagererrors.GenericError:
		return e.StatusCode
	default:
		return http.StatusInternalServerError
	}
}

func match(s string) string {
	i := strings.Index(s, "{")
	if i >= 0 {
		j := strings.Index(s, "}")
		if j >= 0 {
			return s[i+1 : j]
		}
	}
	return ""
}

func middle(in string, field string) (string, string) {
	result := ""
	helper := in
	if strings.Contains(in, field) {
		helper = removeAmpersand(helper)
		indexToCutFrom := strings.Index(helper, field)
		helper = helper[indexToCutFrom:]
		helper = strings.TrimPrefix(helper, field)
		if len(helper) > 0 {
			result = helper[:strings.IndexByte(helper, '}')]
			helper = strings.Replace(removeAmpersand(in), field+result+"}", "", -1)
			//helper = strings.TrimPrefix(in, field+helper+"}")
		}
	}
	return result, helper

}
