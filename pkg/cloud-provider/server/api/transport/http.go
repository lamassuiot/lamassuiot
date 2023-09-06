package transport

import (
	"context"
	"encoding/json"
	"net/http"

	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-provider/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-provider/server/api/endpoint"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-provider/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-provider/server/api/service"
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

func MakeHTTPHandler(s service.Service) http.Handler {
	r := mux.NewRouter()
	e := endpoint.MakeServerEndpoints(s)

	options := []httptransport.ServerOption{
		httptransport.ServerErrorEncoder(encodeError),
	}

	r.Methods("GET").Path("/health").Handler(
		httptransport.NewServer(
			e.HealthEndpoint,
			decodeHealthRequest,
			encodeHealthResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("GET").Path("/config").Handler(
		httptransport.NewServer(
			e.GetConfigurationEndpoint,
			decodeGetConfigurationRequest,
			enocdeGetConnectorsResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("PUT").Path("/config").Handler(
		httptransport.NewServer(
			e.UpdateConfigurationEndpoint,
			decodeUpdateConfigurationRequest,
			encodeUpdateConfigurationResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("PUT").Path("/config").Handler(
		httptransport.NewServer(
			e.UpdateConfigurationEndpoint,
			decodeUpdateConfigurationRequest,
			encodeUpdateConfigurationResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("PUT").Path("/dms/cacerts").Handler(
		httptransport.NewServer(
			e.UpdateDmsCaCerts,
			decodeUpdateDmsCaCertsRequest,
			encodeUpdateDmsCaCertsResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("GET").Path("/devices/{deviceID}/config").Handler(
		httptransport.NewServer(
			e.GetDeviceConfigurationEndpoint,
			decodeGetDeviceConfigRequest,
			enocdeGetDeviceConnectorsResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("PUT").Path("/devices/{deviceID}/certificate").Handler(
		httptransport.NewServer(
			e.UpdateDeviceCertificateStatusEndpoint,
			decodeUpdateDeviceCertificateStatusRequest,
			encodeUpdateDeviceCertificateStatusResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("PUT").Path("/devices/{deviceID}/digital-twin").Handler(
		httptransport.NewServer(
			e.UpdateDeviceDigitalTwinReenrollmentStatusEndpoint,
			decodeUpdateDeviceDigitalTwinReenrollmentStatusRequest,
			encodeUpdateDeviceDigitalTwinReenrollmentStatusResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("POST").Path("/ca").Handler(
		httptransport.NewServer(
			e.RegisterCAEndpoint,
			decodeRegisterCARequest,
			encodeRegisterCAResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("PUT").Path("/ca/{caName}").Handler(
		httptransport.NewServer(
			e.UpdateCAStatusEndpoint,
			decodeUpdateCAStatusRequest,
			decodeUpdateCAStatusResponse,
			append(
				options,
			)...,
		),
	)

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
	type UpdateConfigurationPayload interface{}

	var body UpdateConfigurationPayload
	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	return api.UpdateConfigurationInput{
		Configuration: body,
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

	castedResponse := response.(*api.GetDeviceConfigurationOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeUpdateDeviceCertificateStatusRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var body api.UpdateDeviceCertificateStatusPayload
	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	vars := mux.Vars(r)
	deviceID := vars["deviceID"]

	return api.UpdateDeviceCertificateStatusInput{
		DeviceID:     deviceID,
		CAName:       body.CAName,
		SerialNumber: body.SerialNumber,
		Status:       body.Status,
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
	var body api.RegisterCAPayload
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

func decodeUpdateDmsCaCertsRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var body api.UpdateDMSCaCertPayload
	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	return api.UpdateDMSCaCertsInput{
		DeviceManufacturingService: body.Deserialize(),
	}, nil
}

func encodeUpdateDmsCaCertsResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	castedResponse := response.(*api.UpdateDMSCaCertsOutput)
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

func decodeUpdateDeviceDigitalTwinReenrollmentStatusRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var body api.UpdateDeviceDigitalTwinReenrollmentStatusPayload
	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	vars := mux.Vars(r)
	deviceID := vars["deviceID"]

	return api.UpdateDeviceDigitalTwinReenrollmentStatusInput{
		DeviceID:      deviceID,
		SlotID:        body.SlotID,
		ForceReenroll: body.ForceReenroll,
	}, nil
}

func encodeUpdateDeviceDigitalTwinReenrollmentStatusResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	castedResponse := response.(*api.UpdateDeviceDigitalTwinReenrollmentStatusOutput)
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
