package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/endpoint"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters/types"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/tracing/opentracing"

	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"
	lamassuErrors "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/errors"

	stdopentracing "github.com/opentracing/opentracing-go"
)

type errorer interface {
	error() error
}

func ErrMissingCAName() error {
	return &lamassuErrors.GenericError{
		Message:    "CA name not specified",
		StatusCode: 400,
	}
}
func ErrMissingCAType() error {
	return &lamassuErrors.GenericError{
		Message:    "CA type not specified",
		StatusCode: 400,
	}
}
func ErrMissingSerialNumber() error {
	return &lamassuErrors.GenericError{
		Message:    "serial number type not specified",
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

func filtrableCAModelFields() map[string]types.Filter {
	fieldFiltersMap := make(map[string]types.Filter)
	fieldFiltersMap["status"] = &types.StringFilterField{}
	fieldFiltersMap["serial_number"] = &types.StringFilterField{}
	fieldFiltersMap["name"] = &types.StringFilterField{}
	fieldFiltersMap["valid_from"] = &types.DatesFilterField{}
	fieldFiltersMap["valid_to"] = &types.DatesFilterField{}
	return fieldFiltersMap
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

	r.Methods("GET").Path("/stats").Handler(httptransport.NewServer(
		e.StatsEndpoint,
		decodeStatsRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "Stats", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	// Get all CAs
	r.Methods("GET").Path("/{caType}").Handler(httptransport.NewServer(
		e.GetCAsEndpoint,
		decodeGetCAsRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetCAs", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	// Create new CA using Form
	r.Methods("POST").Path("/pki/{caName}").Handler(httptransport.NewServer(
		e.CreateCAEndpoint,
		decodeCreateCARequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "CreateCA", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	// Import existing crt and key
	r.Methods("POST").Path("/pki/import/{caName}").Handler(httptransport.NewServer(
		e.ImportCAEndpoint,
		decodeImportCARequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "ImportCA", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	// Revoke CA
	r.Methods("DELETE").Path("/pki/{caName}").Handler(httptransport.NewServer(
		e.DeleteCAEndpoint,
		decodeDeleteCARequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "DeleteCA", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	// Get Issued certificates by {ca}
	r.Methods("GET").Path("/{caType}/{caName}/issued").Handler(httptransport.NewServer(
		e.GetIssuedCertsEndpoint,
		decodeGetIssuedCertsRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetIssuedCerts", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	// Get certificate by {ca} and {serialNumber}
	r.Methods("GET").Path("/{caType}/{caName}/cert/{serialNumber}").Handler(httptransport.NewServer(
		e.GetCertEndpoint,
		decodeGetCertRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetCert", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	// Sign CSR by {ca}
	r.Methods("POST").Path("/{caType}/{caName}/sign").Handler(httptransport.NewServer(
		e.SignCertEndpoint,
		decodeSignCertificateRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "SignCSR", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	// Revoke certificate issued by {ca} and {serialNumber}
	r.Methods("DELETE").Path("/{caType}/{caName}/cert/{serialNumber}").Handler(httptransport.NewServer(
		e.DeleteCertEndpoint,
		decodeDeleteCertRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "DeleteCert", logger)),
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
	var req endpoint.StatsRequest
	return req, nil
}

func decodeGetCAsRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	caTypeString, ok := vars["caType"]
	if !ok {
		return nil, ErrMissingCAType()
	}

	return endpoint.GetCAsRequest{
		CaType: caTypeString,
	}, nil

}

func decodeGetIssuedCertsRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	caName, ok := vars["caName"]
	if !ok {
		return nil, ErrMissingCAName()
	}
	caTypeString, ok := vars["caType"]
	if !ok {
		return nil, ErrMissingCAType()
	}

	caType, err := dto.ParseCAType(caTypeString)
	if err != nil {
		return nil, err
	}
	return endpoint.GetIssuedCertsRequest{
		CaType:          caType,
		CA:              caName,
		QueryParameters: filters.FilterQuery(r, filtrableCAModelFields()),
	}, nil
}

func decodeCreateCARequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	var createCaRequest endpoint.CreateCARequest
	json.NewDecoder(r.Body).Decode(&createCaRequest.CaPayload)
	if err != nil {
		return nil, errors.New("cannot decode JSON request")
	}

	caName, ok := vars["caName"]
	if !ok {
		return nil, ErrMissingCAName()
	}

	createCaRequest.CaName = caName
	createCaRequest.CaType = "pki"

	return createCaRequest, nil
}

func decodeImportCARequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	var importCaRequest endpoint.ImportCARequest
	json.NewDecoder(r.Body).Decode(&importCaRequest.CaPayload)
	if err != nil {
		return nil, errors.New("Cannot decode JSON request")
	}

	caName, ok := vars["caName"]
	if !ok {
		return nil, ErrMissingCAName()
	}

	importCaRequest.CaName = caName
	importCaRequest.CaType = "pki"

	return importCaRequest, nil
}

func decodeDeleteCARequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	CA, ok := vars["caName"]
	if !ok {
		return nil, ErrMissingCAName()
	}
	return endpoint.DeleteCARequest{
		CaType: dto.Pki,
		CA:     CA,
	}, nil
}

func decodeGetCertRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	caName, ok := vars["caName"]
	if !ok {
		return nil, ErrMissingCAName()
	}
	caTypeString, ok := vars["caType"]
	if !ok {
		return nil, ErrMissingCAType()
	}

	caType, err := dto.ParseCAType(caTypeString)
	if err != nil {
		return nil, err
	}
	serialNumber, ok := vars["serialNumber"]
	if !ok {
		return nil, ErrMissingSerialNumber()
	}
	return endpoint.GetCertRequest{
		CaType:       caType,
		CaName:       caName,
		SerialNumber: serialNumber,
	}, nil
}

func decodeSignCertificateRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	caName, ok := vars["caName"]
	if !ok {
		return nil, ErrMissingCAName()
	}
	caType, ok := vars["caType"]
	if !ok {
		return nil, ErrMissingCAType()
	}

	var signRequest endpoint.SignCertificateRquest

	json.NewDecoder(r.Body).Decode(&signRequest.SignPayload)
	if err != nil {
		return nil, errors.New("Cannot decode JSON request")
	}

	signRequest.CaName = caName
	signRequest.CaType = caType

	return signRequest, nil
}

func decodeDeleteCertRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	ca, ok := vars["caName"]
	if !ok {
		return nil, ErrMissingCAName()
	}
	caTypeString, ok := vars["caType"]
	if !ok {
		return nil, ErrMissingCAType()
	}

	caType, err := dto.ParseCAType(caTypeString)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, ErrMissingCAName()
	}
	serialNumber, ok := vars["serialNumber"]
	if !ok {
		return nil, ErrMissingSerialNumber()
	}
	return endpoint.DeleteCertRequest{
		CaType:       caType,
		CaName:       ca,
		SerialNumber: serialNumber,
	}, nil
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
