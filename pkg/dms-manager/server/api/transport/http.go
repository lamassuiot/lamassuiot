package transport

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/endpoint"
	dmsErrors "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common/types"
	serverUtils "github.com/lamassuiot/lamassuiot/pkg/utils/server"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
	stdopentracing "github.com/opentracing/opentracing-go"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
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

func MakeHTTPHandler(s service.Service, logger log.Logger, otTracer stdopentracing.Tracer) http.Handler {
	r := mux.NewRouter()
	e := endpoint.MakeServerEndpoints(s, otTracer)
	options := []httptransport.ServerOption{
		httptransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		httptransport.ServerErrorEncoder(encodeError),
	}

	r.Methods("GET").Path("/health").Handler(
		serverUtils.InjectTracingToContext(
			otelhttp.NewHandler(
				httptransport.NewServer(
					e.HealthEndpoint,
					decodeHealthRequest,
					encodeHealthResponse,
					append(
						options,
					)...,
				),
				"Health",
			),
		),
	)

	r.Methods("POST").Path("/").Handler(
		serverUtils.InjectTracingToContext(
			otelhttp.NewHandler(
				httptransport.NewServer(
					e.CreateDMSEndpoint,
					decodeCreateDMSRequest,
					encodeCreateDMSResponse,
					append(
						options,
					)...,
				),
				"CreateDMS",
			),
		),
	)

	r.Methods("POST").Path("/csr").Handler(
		serverUtils.InjectTracingToContext(
			otelhttp.NewHandler(
				httptransport.NewServer(
					e.CreateDMSWithCSREndpoint,
					decodeCreateDMSWithCSRequest,
					encodeCreateDMSWithCSRResponse,
					append(
						options,
					)...,
				),
				"CreateDMSWithCSR",
			),
		),
	)

	r.Methods("GET").Path("/").Handler(
		serverUtils.InjectTracingToContext(
			otelhttp.NewHandler(
				httptransport.NewServer(
					e.GetDMSsEndpoint,
					decodeGetDMSsRequest,
					encodeGetDMSsResponse,
					append(
						options,
					)...,
				),
				"GetDMSs",
			),
		),
	)

	r.Methods("GET").Path("/{name}").Handler(
		serverUtils.InjectTracingToContext(
			otelhttp.NewHandler(
				httptransport.NewServer(
					e.GetDMSByNameEndpoint,
					decodeGetDMSByNameRequest,
					encodeGetDMSByNameResponse,
					append(
						options,
					)...,
				),
				"GetDMSByName",
			),
		),
	)

	r.Methods("PUT").Path("/{name}/status").Handler(
		serverUtils.InjectTracingToContext(
			otelhttp.NewHandler(
				httptransport.NewServer(
					e.UpdateDMSStatusEndpoint,
					decodeUpdateDMSStatusRequest,
					encodeUpdateDMSStatusResponse,
					append(
						options,
					)...,
				),
				"UpdateDMSStatus",
			),
		),
	)

	r.Methods("PUT").Path("/{name}/auth").Handler(
		serverUtils.InjectTracingToContext(
			otelhttp.NewHandler(
				httptransport.NewServer(
					e.UpdateDMSAuthorizedCAsEndpoint,
					decodeUpdateDMSAuthorizedCAsRequest,
					encodeUpdateDMSAuthorizedCAsResponse,
					append(
						options,
					)...,
				),
				"UpdateAuthorizedCAs",
			),
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
		Subject: api.Subject{
			CommonName:       body.Subject.CommonName,
			Organization:     body.Subject.Organization,
			OrganizationUnit: body.Subject.OrganizationUnit,
			Country:          body.Subject.Country,
			State:            body.Subject.State,
			Locality:         body.Subject.Locality,
		},
		KeyMetadata: api.KeyMetadata{
			KeyType: api.ParseKeyType(body.KeyMetadata.KeyType),
			KeyBits: body.KeyMetadata.KeyBits,
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

func decodeCreateDMSWithCSRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {

	var input api.CreateDMSWithCertificateRequestInput
	var body api.CreateDMSWithCertificateRequestPayload

	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	decodedCertBytes, err := base64.StdEncoding.DecodeString(body.CertificateRequest)
	if err != nil {
		return nil, InvalidJsonFormat()
	}
	decodedCert := strings.Trim(string(decodedCertBytes), "\n")
	if err != nil {
		return api.CreateDMSWithCertificateRequestInput{}, &dmsErrors.GenericError{
			StatusCode: http.StatusBadRequest,
			Message:    dmsErrors.ErrSignRequestNotInB64,
		}
	}

	certBlock, _ := pem.Decode([]byte(decodedCert))
	if certBlock == nil {
		return api.CreateDMSWithCertificateRequestInput{}, &dmsErrors.GenericError{
			StatusCode: http.StatusBadRequest,
			Message:    dmsErrors.ErrSignRequestNotInPEMFormat,
		}
	}
	certRequest, err := x509.ParseCertificateRequest(certBlock.Bytes)
	if err != nil {
		return api.CreateDMSWithCertificateRequestInput{}, errors.New("could not inflate certificate request")
	}

	input = api.CreateDMSWithCertificateRequestInput{
		CertificateRequest: certRequest,
	}

	return input, nil
}

func encodeCreateDMSWithCSRResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}

	castedResponse := response.(*api.CreateDMSWithCertificateRequestOutput)
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
