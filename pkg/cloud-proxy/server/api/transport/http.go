package transport

import (
	"context"
	"encoding/json"
	"net/http"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/go-kit/log"

	"github.com/gorilla/mux"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/endpoint"
	lamassuErrors "github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type errorer interface {
	error() error
}

func ErrMissingConnectorID() error {
	return &lamassuErrors.GenericError{
		Message:    "connectorID not specified",
		StatusCode: 400,
	}
}
func ErrMissingCaName() error {
	return &lamassuErrors.GenericError{
		Message:    "CA Name not specified",
		StatusCode: 400,
	}
}
func ErrMissingDeviceID() error {
	return &lamassuErrors.GenericError{
		Message:    "deviceID not specified",
		StatusCode: 400,
	}
}
func HTTPToContext(logger log.Logger) httptransport.RequestFunc {
	return func(ctx context.Context, req *http.Request) context.Context {
		// Try to join to a trace propagated in `req`.
		uberTraceId := req.Header.Values("Uber-Trace-Id")
		if uberTraceId != nil {
			logger = log.With(logger, "span_id", uberTraceId)
		} else {
			span := stdopentracing.SpanFromContext(ctx)
			logger = log.With(logger, "span_id", span)
		}
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

	r.Methods("GET").Path("/health").Handler(httptransport.NewServer(
		e.HealthEndpoint,
		decodeHealthRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "Health", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/connectors").Handler(httptransport.NewServer(
		e.GetCloudConnectorsEndpoint,
		decodeEmptyRequest,
		enocdeGetConnectorsResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetCloudConnectorsEndpoint", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/connectors/{connectorID}/devices/{deviceID}").Handler(httptransport.NewServer(
		e.GetDeviceConfigurationEndpoint,
		decodeGetDeviceConfigByID,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetCloudConnectorsDevicesEndpoint", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("POST").Path("/connectors/synchronize").Handler(httptransport.NewServer(
		e.SynchronizedCAEndpoint,
		decodeSynchronizeCARequest,
		enocdeSynchronizeCAResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "SynchronizedCAEndpoint", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("PUT").Path("/connectors/{connectorID}/access-policy").Handler(httptransport.NewServer(
		e.UpdateSecurityAccessPolicy,
		decodeUpdateSecurityAccessPolicyRequest,
		enocdeUpdateSecurityAccessPolicyResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "UpdateSecurityAccessPolicy", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("POST").Path("/event").Handler(httptransport.NewServer(
		e.EventHandlerEndpoint,
		decodeEventHandlerRequest,
		encodeEventHandlerResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "EventHandlerEndpoint", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("PUT").Path("/connectors/{connectorID}/devices/{deviceID}/cert").Handler(httptransport.NewServer(
		e.UpdateDeviceCertStatusEndpoint,
		decodeUpdateDeviceCertStatusRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "UpdateDeviceCertStatus", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))
	r.Methods("PUT").Path("/{caName}").Handler(httptransport.NewServer(
		e.UpdateCaStatusEndpoint,
		decodeUpdateCaStatusRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "UpdateCaStatusEndpoint", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))
	return r
}

func decodeHealthRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var req endpoint.HealthRequest
	return req, nil
}

func decodeEmptyRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var req endpoint.EmptyRequest
	return req, nil
}
func decodeGetDeviceConfigByID(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	var deviceRequest endpoint.GetDeviceConfigurationRequest

	connectorID, ok := vars["connectorID"]
	if !ok {
		return nil, ErrMissingConnectorID()
	}

	deviceID, ok := vars["deviceID"]
	if !ok {
		return nil, ErrMissingDeviceID()
	}

	deviceRequest.ConnectorID = connectorID
	deviceRequest.DeviceID = deviceID
	return deviceRequest, nil
}
func decodeSynchronizeCARequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var synchronizeCA endpoint.SynchronizeCARequest
	err = json.NewDecoder(r.Body).Decode(&synchronizeCA)
	if err != nil {
		return nil, &lamassuErrors.GenericError{
			Message:    "Could not deserialize JSON Content",
			StatusCode: 400,
		}
	}
	return synchronizeCA, nil
}

func decodeUpdateSecurityAccessPolicyRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	var updateRequest endpoint.UpdateSecurityAccessPolicyRequest

	connectorID, ok := vars["connectorID"]
	if !ok {
		return nil, ErrMissingConnectorID()
	}

	err = json.NewDecoder(r.Body).Decode(&updateRequest.Payload)
	if err != nil {
		return nil, &lamassuErrors.GenericError{
			Message:    "Could not deserialize JSON Content",
			StatusCode: 400,
		}
	}
	updateRequest.ConnectorID = connectorID
	return updateRequest, nil
}
func decodeUpdateDeviceCertStatusRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	var updateRequest endpoint.UpdateDeviceCertStatusRequest

	connectorID, ok := vars["connectorID"]
	if !ok {
		return nil, ErrMissingConnectorID()
	}
	deviceID, ok := vars["deviceID"]
	if !ok {
		return nil, ErrMissingDeviceID()
	}
	err = json.NewDecoder(r.Body).Decode(&updateRequest.Payload)
	if err != nil {
		return nil, &lamassuErrors.GenericError{
			Message:    "Could not deserialize JSON Content",
			StatusCode: 400,
		}
	}
	updateRequest.ConnectorID = connectorID
	updateRequest.DeviceID = deviceID
	return updateRequest, nil
}
func decodeUpdateCaStatusRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	var updateRequest endpoint.UpdateCaStatusRequest

	caName, ok := vars["caName"]
	if !ok {
		return nil, ErrMissingCaName()
	}
	err = json.NewDecoder(r.Body).Decode(&updateRequest.Payload)
	if err != nil {
		return nil, &lamassuErrors.GenericError{
			Message:    "Could not deserialize JSON Content",
			StatusCode: 400,
		}
	}
	updateRequest.CaName = caName
	return updateRequest, nil
}
func decodeEventHandlerRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var event cloudevents.Event
	json.NewDecoder(r.Body).Decode((&event))
	return event, nil
}

// func encodeGetSynchronizedCAsByConnectorRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
// 	encodeResponse()
// }

func enocdeGetConnectorsResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)

		return nil
	}
	activeCloudConnectors := response.(endpoint.GetActiveCloudConnectorsResponse)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(activeCloudConnectors.CloudConnectors)
}

func enocdeSynchronizeCAResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)

		return nil
	}
	syncCAResponse := response.(endpoint.SynchronizedCAResponse)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(syncCAResponse.CloudConnector)
}

func enocdeUpdateSecurityAccessPolicyResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)

		return nil
	}
	updateSecurityAccessPolicyResponse := response.(endpoint.UpdateSecurityAccessPolicyResponse)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(updateSecurityAccessPolicyResponse.CloudConnector)
}

func encodeEventHandlerResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)

		return nil
	}
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(response)
}

func encodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		// Not a Go kit transport error, but a business-logic error.
		// Provide those as HTTP errors.

		// https://medium.com/@ozdemir.zynl/rest-api-error-handling-in-go-behavioral-type-assertion-509d93636afd
		//
		encodeError(ctx, e.error(), w)

		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

func encodeError(ctx context.Context, err error, w http.ResponseWriter) {
	if err == nil {
		panic("encodeError with nil error")
	}
	w.WriteHeader(codeFrom(err))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	json.NewEncoder(w).Encode(errorWrapper{Error: err.Error()})

}

type errorWrapper struct {
	Error string `json:"error"`
}

func codeFrom(err error) int {
	switch e := err.(type) {
	case *lamassuErrors.ValidationError:
		return http.StatusBadRequest
	case *lamassuErrors.DuplicateResourceError:
		return http.StatusConflict
	case *lamassuErrors.ResourceNotFoundError:
		return http.StatusNotFound
	case *lamassuErrors.GenericError:
		return e.StatusCode
	default:
		return http.StatusInternalServerError
	}
}
