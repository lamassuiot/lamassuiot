package transport

import (
	"context"
	"encoding/json"
	"net/http"

	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/endpoint"
	dmsErrors "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common/types"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
)

type errorer interface {
	error() error
}

func InvalidJsonFormat() error {
	return &dmsErrors.GenericError{
		Message:    "Invalid JSON format",
		StatusCode: 400,
	}
}
func ErrMissingDMSStatus() error {
	return &dmsErrors.GenericError{
		Message:    "DMS status not specified",
		StatusCode: 400,
	}
}

func filtrableDMSModelFields() map[string]types.Filter {
	fieldFiltersMap := make(map[string]types.Filter)
	fieldFiltersMap["name"] = &types.StringFilterField{}
	fieldFiltersMap["status"] = &types.StringFilterField{}
	fieldFiltersMap["creation_timestamp"] = &types.DatesFilterField{}
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

	r.Methods("POST").Path("/").Handler(
		httptransport.NewServer(
			e.CreateDMSEndpoint,
			decodeCreateDMSRequest,
			encodeCreateDMSResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("GET").Path("/").Handler(
		httptransport.NewServer(
			e.GetDMSsEndpoint,
			decodeGetDMSsRequest,
			encodeGetDMSsResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("GET").Path("/{name}").Handler(
		httptransport.NewServer(
			e.GetDMSByNameEndpoint,
			decodeGetDMSByNameRequest,
			encodeGetDMSByNameResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("PUT").Path("/{name}/status").Handler(
		httptransport.NewServer(
			e.UpdateDMSStatusEndpoint,
			decodeUpdateDMSStatusRequest,
			encodeUpdateDMSStatusResponse,
			append(
				options,
			)...,
		),
	)

	r.Methods("PUT").Path("/{name}/auth").Handler(
		httptransport.NewServer(
			e.UpdateDMSAuthorizedCAsEndpoint,
			decodeUpdateDMSAuthorizedCAsRequest,
			encodeUpdateDMSAuthorizedCAsResponse,
			append(
				options,
			)...,
		),
	)
	r.Methods("PUT").Path("/").Handler(
		httptransport.NewServer(
			e.UpdateDMSEndpoint,
			decodeUpdateDMSRequest,
			encodeUpdateDMSResponse,
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

func decodeCreateDMSRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {

	var input api.CreateDMSInput
	var body api.CreateDMSPayload

	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	input = api.CreateDMSInput{
		DeviceManufacturingService: api.DeviceManufacturingService{
			Name:                 body.Name,
			CloudDMS:             body.CloudDMS,
			IdentityProfile:      body.IdentityProfile.Deserialize(),
			RemoteAccessIdentity: body.RemoteAccessIdentity.Deserialize(),
		},
	}

	return input, nil
}

func encodeCreateDMSResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(*api.CreateDMSOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeUpdateDMSRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {

	var input api.UpdateDMSInput
	var body api.DeviceManufacturingServiceSerialized

	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	input = api.UpdateDMSInput{
		DeviceManufacturingService: body.Deserialize(),
	}

	return input, nil
}

func encodeUpdateDMSResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(*api.UpdateDMSOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeGetDMSsRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	return api.GetDMSsInput{
		QueryParameters: filters.FilterQuery(r, filtrableDMSModelFields()),
	}, nil
}

func encodeGetDMSsResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(*api.GetDMSsOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeGetDMSByNameRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	dmsName := vars["name"]

	return api.GetDMSByNameInput{
		Name: dmsName,
	}, nil
}

func encodeGetDMSByNameResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(*api.GetDMSByNameOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeUpdateDMSStatusRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	dmsName := vars["name"]

	var body api.UpdateDMSStatusPayload

	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	status, err := api.ParseDMSStatus(body.Status)
	if err != nil {
		return nil, &dmsErrors.GenericError{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
	}

	return api.UpdateDMSStatusInput{
		Name:   dmsName,
		Status: status,
	}, nil
}

func encodeUpdateDMSStatusResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(*api.UpdateDMSStatusOutput)
	serializedResponse := castedResponse.Serialize()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(serializedResponse)
}

func decodeUpdateDMSAuthorizedCAsRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	dmsName := vars["name"]

	var body api.UpdateDMSAuthorizedCAsPayload

	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	return api.UpdateDMSAuthorizedCAsInput{
		Name:          dmsName,
		AuthorizedCAs: body.AuthorizedCAs,
	}, nil
}

func encodeUpdateDMSAuthorizedCAsResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(*api.UpdateDMSAuthorizedCAsOutput)
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
	case *dmsErrors.ValidationError:
		return http.StatusBadRequest
	case *dmsErrors.DuplicateResourceError:
		return http.StatusConflict
	case *dmsErrors.ResourceNotFoundError:
		return http.StatusNotFound
	case *dmsErrors.GenericError:
		return e.StatusCode
	default:
		return http.StatusInternalServerError
	}
}
