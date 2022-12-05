package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/endpoint"
	devmanagererrors "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common/types"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
)

type errorer interface {
	error() error
}

func InvalidJsonFormat() error {
	return &devmanagererrors.GenericError{
		Message:    "Invalid JSON format",
		StatusCode: 400,
	}
}

func filtrableDeviceModelFields() map[string]types.Filter {
	fieldFiltersMap := make(map[string]types.Filter)
	fieldFiltersMap["id"] = &types.StringFilterField{}
	fieldFiltersMap["description"] = &types.StringFilterField{}
	fieldFiltersMap["alias"] = &types.StringFilterField{}
	fieldFiltersMap["status"] = &types.StringFilterField{}
	fieldFiltersMap["dms_id"] = &types.StringFilterField{}
	fieldFiltersMap["creation_ts"] = &types.DatesFilterField{}
	return fieldFiltersMap
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

	r.Methods("GET").Path("/stats").Handler(
		httptransport.NewServer(
			e.GetStatsEndpoint,
			decodeGetStatsRequest,
			encodeGetStatsResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("POST").Path("/devices").Handler(
		httptransport.NewServer(
			e.CreateDeviceEndpoint,
			decodeCreateDeviceRequest,
			encodeCreateDeviceResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("GET").Path("/devices").Handler(
		httptransport.NewServer(
			e.GetDevicesEndpoint,
			decodeGetDevicesRequest,
			encodeGetDevicesResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("GET").Path("/devices/{deviceID}").Handler(
		httptransport.NewServer(
			e.GetDeviceByIdEndpoint,
			decodeGetDeviceByIdRequest,
			encodeGetDeviceByIdResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("PUT").Path("/devices/{deviceID}").Handler(
		httptransport.NewServer(
			e.UpdateDeviceMetadataEndpoint,
			decodeUpdateDeviceMetadataRequest,
			encodeUpdateDeviceMetadataResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("DELETE").Path("/devices/{deviceID}").Handler(
		httptransport.NewServer(
			e.DecommisionDeviceEndpoint,
			decodeDecommisionDeviceRequest,
			encodeDecommisionDeviceResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("DELETE").Path("/devices/{deviceID}/slots/{slotID}").Handler(
		httptransport.NewServer(
			e.RevokeActiveCertificateEndpoint,
			decodeRevokeActiveCertificateRequest,
			encodeRevokeActiveCertificateResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("PUT").Path("/devices/{deviceID}/slots/{slotID}").Handler(
		httptransport.NewServer(
			e.ForceReenrollEndpoint,
			decodeForceReenrollRequest,
			encodeForceReenrollResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("GET").Path("/devices/{deviceID}/logs").Handler(
		httptransport.NewServer(
			e.GetDeviceLogsEndpoint,
			decodeGetDeviceLogsRequest,
			encodeGetDeviceLogsResponse,
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

func decodeGetStatsRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	forceRefreshString := r.URL.Query().Get("force_refresh")
	forceRefresh := false
	if forceRefreshString != "" {
		parsedForceRefresh, err := strconv.ParseBool(forceRefreshString)
		if err == nil {
			forceRefresh = parsedForceRefresh
		}
	}

	return api.GetStatsInput{
		ForceRefresh: forceRefresh,
	}, nil
}
func encodeGetStatsResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	castedResponse := response.(*api.GetStatsOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeCreateDeviceRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	type CreateDevicePayload struct {
		DeviceID    string   `json:"id"`
		Alias       string   `json:"alias"`
		Tags        []string `json:"tags"`
		Description string   `json:"description"`
		IconColor   string   `json:"icon_color"`
		IconName    string   `json:"icon_name"`
	}

	var input api.CreateDeviceInput
	var body CreateDevicePayload

	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	input = api.CreateDeviceInput{
		DeviceID:    body.DeviceID,
		Alias:       body.Alias,
		Tags:        body.Tags,
		Description: body.Description,
		IconColor:   body.IconColor,
		IconName:    body.IconName,
	}

	return input, nil
}
func encodeCreateDeviceResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	castedResponse := response.(*api.CreateDeviceOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeUpdateDeviceMetadataRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	type UpdateDeviceMetadataPayload struct {
		Alias       string   `json:"alias"`
		Tags        []string `json:"tags"`
		Description string   `json:"description"`
		IconColor   string   `json:"icon_color"`
		IconName    string   `json:"icon_name"`
	}

	var input api.UpdateDeviceMetadataInput
	var body UpdateDeviceMetadataPayload

	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	vars := mux.Vars(r)
	deviceID := vars["deviceID"]

	input = api.UpdateDeviceMetadataInput{
		DeviceID:    deviceID,
		Alias:       body.Alias,
		Tags:        body.Tags,
		Description: body.Description,
		IconColor:   body.IconColor,
		IconName:    body.IconName,
	}

	return input, nil
}
func encodeUpdateDeviceMetadataResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	castedResponse := response.(*api.UpdateDeviceMetadataOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeDecommisionDeviceRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	deviceID := vars["deviceID"]

	return api.DecommisionDeviceInput{
		DeviceID: deviceID,
	}, nil
}
func encodeDecommisionDeviceResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	castedResponse := response.(*api.DecommisionDeviceOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeGetDevicesRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	return api.GetDevicesInput{
		QueryParameters: filters.FilterQuery(r, filtrableDeviceModelFields()),
	}, nil
}

func encodeGetDevicesResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	castedResponse := response.(*api.GetDevicesOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeGetDeviceByIdRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	deviceID := vars["deviceID"]

	return api.GetDeviceByIdInput{
		DeviceID: deviceID,
	}, nil
}
func encodeGetDeviceByIdResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	castedResponse := response.(*api.GetDeviceByIdOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeRevokeActiveCertificateRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	type RevokeActiveCertificatePayload struct {
		RevocationReason string `json:"revocation_reason"`
	}

	var body RevokeActiveCertificatePayload

	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	vars := mux.Vars(r)
	deviceID := vars["deviceID"]
	slotID := vars["slotID"]

	return api.RevokeActiveCertificateInput{
		DeviceID:         deviceID,
		SlotID:           slotID,
		RevocationReason: body.RevocationReason,
	}, nil
}
func encodeRevokeActiveCertificateResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	castedResponse := response.(*api.RevokeActiveCertificateOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeForceReenrollRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	type ForceReenrollPayload struct {
		ForceReenroll bool `json:"require_reenrollment"`
	}
	var body ForceReenrollPayload

	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}
	vars := mux.Vars(r)
	deviceID := vars["deviceID"]
	slotID := vars["slotID"]

	return api.ForceReenrollInput{
		DeviceID:      deviceID,
		SlotID:        slotID,
		ForceReenroll: body.ForceReenroll,
	}, nil
}
func encodeForceReenrollResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	castedResponse := response.(*api.ForceReenrollOtput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeGetDeviceLogsRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	deviceID := vars["deviceID"]

	return api.GetDeviceLogsInput{
		DeviceID: deviceID,
	}, nil
}
func encodeGetDeviceLogsResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	castedResponse := response.(*api.GetDeviceLogsOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
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
	case *devmanagererrors.DuplicateResourceError:
		return http.StatusNotFound
	case *devmanagererrors.ResourceNotFoundError:
		return http.StatusNotFound
	case *devmanagererrors.GenericError:
		return e.StatusCode
	default:
		return http.StatusInternalServerError
	}
}
