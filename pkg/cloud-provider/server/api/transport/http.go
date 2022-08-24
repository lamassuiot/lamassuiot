package transport

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	caApi "github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-provider/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-provider/server/api/endpoint"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-provider/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-provider/server/api/service"
	utilstransport "github.com/lamassuiot/lamassuiot/pkg/utils/server/transport"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type errorer interface {
	error() error
}

func InvalidJsonFormat() error {
	return &errors.GenericError{
		Message:    "Invalid JSON format",
		StatusCode: 400,
	}
}

func MakeHTTPHandler(s service.Service, logger log.Logger, otTracer stdopentracing.Tracer) http.Handler {
	r := mux.NewRouter()
	e := endpoint.MakeServerEndpoints(s, otTracer)

	options := []httptransport.ServerOption{
		httptransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		httptransport.ServerErrorEncoder(encodeError),
		httptransport.ServerBefore(utilstransport.HTTPToContext(logger)),
	}

	r.Methods("GET").Path("/health").Handler(httptransport.NewServer(
		e.HealthEndpoint,
		decodeHealthRequest,
		encodeHealthResponse,
		append(options, httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetConfig", logger)))...,
	))

	r.Methods("GET").Path("/config").Handler(httptransport.NewServer(
		e.GetConfigurationEndpoint,
		decodeGetConfigurationRequest,
		enocdeGetConnectorsResponse,
		append(options, httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetConfig", logger)))...,
	))

	r.Methods("PUT").Path("/config").Handler(httptransport.NewServer(
		e.UpdateConfigurationEndpoint,
		decodeUpdateConfigurationRequest,
		encodeUpdateConfigurationResponse,
		append(options, httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "UpdateConfig", logger)))...,
	))

	r.Methods("GET").Path("/devices/{deviceID}/config").Handler(httptransport.NewServer(
		e.GetDeviceConfigurationEndpoint,
		decodeGetDeviceConfigRequest,
		enocdeGetDeviceConnectorsResponse,
		append(options, httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetDevicesConfig", logger)))...,
	))

	r.Methods("PUT").Path("/certificate").Handler(httptransport.NewServer(
		e.UpdateDeviceCertificateStatusEndpoint,
		decodeUpdateDeviceCertificateStatusRequest,
		encodeUpdateDeviceCertificateStatusResponse,
		append(options, httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "UpdateCertStatus", logger)))...,
	))

	r.Methods("POST").Path("/ca").Handler(httptransport.NewServer(
		e.RegisterCAEndpoint,
		decodeRegisterCARequest,
		encodeRegisterCAResponse,
		append(options, httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "CreateCA", logger)))...,
	))

	r.Methods("PUT").Path("/ca/{caName}").Handler(httptransport.NewServer(
		e.UpdateCAStatusEndpoint,
		decodeUpdateCAStatusRequest,
		decodeUpdateCAStatusResponse,
		append(options, httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "UpdateCAStatus", logger)))...,
	))

	return r
}

func decodeHealthRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	return nil, nil
}

func encodeHealthResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}
func decodeGetConfigurationRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	return api.GetConfigurationInput{}, nil
}

func enocdeGetConnectorsResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	castedResponse := response.(*api.GetConfigurationOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeUpdateConfigurationRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	type UpdateConfigurationPayload struct {
		Configuration interface{} `json:"configuration"`
	}

	var body UpdateConfigurationPayload
	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	return api.UpdateConfigurationInput{
		Configuration: body.Configuration,
	}, nil
}

func encodeUpdateConfigurationResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	castedResponse := response.(*api.UpdateConfigurationOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeGetDeviceConfigRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	deviceID := vars["deviceID"]

	return api.GetDeviceConfigurationInput{
		DeviceID: deviceID,
	}, nil
}

func enocdeGetDeviceConnectorsResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	castedResponse := response.(*api.GetConfigurationOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeUpdateDeviceCertificateStatusRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	type UpdateDeviceCertificateStatusPayload struct {
		Certificate caApi.CertificateSerialized `json:"certificate"`
		Status      string                      `json:"status"`
	}

	var body UpdateDeviceCertificateStatusPayload
	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	return api.UpdateDeviceCertificateStatusInput{
		Certificate: body.Certificate.Deserialize(),
		Status:      body.Status,
	}, nil
}

func encodeUpdateDeviceCertificateStatusResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	castedResponse := response.(*api.UpdateDeviceCertificateStatusOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeRegisterCARequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	type RegisterCAPayload struct {
		caApi.CACertificateSerialized
	}

	var body RegisterCAPayload
	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	return api.RegisterCAInput{
		CACertificate: body.Deserialize(),
	}, nil
}

func encodeRegisterCAResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	castedResponse := response.(*api.RegisterCAOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeUpdateCAStatusRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	caName := vars["caName"]

	type UpdateCAStatusPayload struct {
		Status string `json:"status"`
	}

	var body UpdateCAStatusPayload
	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	return api.UpdateCAStatusInput{
		CAName: caName,
		Status: body.Status,
	}, nil
}

func decodeUpdateCAStatusResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	castedResponse := response.(*api.UpdateCAStatusOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func encodeError(ctx context.Context, err error, w http.ResponseWriter) {
	if err == nil {
		panic("encodeError with nil error")
	}
	// http.Error(w, err.Error(), codeFrom(err))
	w.WriteHeader(codeFrom(err))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	json.NewEncoder(w).Encode(errorWrapper{Error: err.Error()})

}

type errorWrapper struct {
	Error string `json:"error"`
}

func codeFrom(err error) int {
	switch e := err.(type) {
	case *errors.ValidationError:
		return http.StatusBadRequest
	case *errors.DuplicateResourceError:
		return http.StatusConflict
	case *errors.ResourceNotFoundError:
		return http.StatusNotFound
	case *errors.GenericError:
		return e.StatusCode
	default:
		return http.StatusInternalServerError
	}
}
