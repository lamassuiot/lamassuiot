package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/endpoint"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/utils"

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

func InvalidJsonFormat() error {
	return &lamassuErrors.GenericError{
		Message:    "Invalid JSON format",
		StatusCode: 400,
	}
}
func InvalidCaType() error {
	return &lamassuErrors.GenericError{
		Message:    "Invalid CA Type",
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
	caTypeString, _ := vars["caType"]

	return endpoint.GetCAsRequest{
		CaType: caTypeString,
	}, nil

}

func decodeGetIssuedCertsRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	caName, _ := vars["caName"]
	caTypeString, _ := vars["caType"]

	caType, err := dto.ParseCAType(caTypeString)
	if err != nil {
		return nil, InvalidCaType()
	}
	return endpoint.GetIssuedCertsRequest{
		CaType:          caType,
		CA:              caName,
		QueryParameters: filterQuery(r),
	}, nil
}

func decodeCreateCARequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	var createCaRequest endpoint.CreateCARequest
	err = json.NewDecoder(r.Body).Decode(&createCaRequest.CaPayload)
	if err != nil {
		return nil, InvalidJsonFormat()
	}
	caName, _ := vars["caName"]

	createCaRequest.CaName = caName
	createCaRequest.CaType = "pki"

	return createCaRequest, nil
}

func decodeImportCARequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	var importCaRequest endpoint.ImportCARequest
	err = json.NewDecoder(r.Body).Decode(&importCaRequest.CaPayload)
	if err != nil {
		return nil, InvalidJsonFormat()
	}
	caName, _ := vars["caName"]

	importCaRequest.CaName = caName
	importCaRequest.CaType = "pki"

	return importCaRequest, nil
}

func decodeDeleteCARequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	CA, _ := vars["caName"]

	return endpoint.DeleteCARequest{
		CaType: dto.Pki,
		CA:     CA,
	}, nil
}

func decodeGetCertRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	caName, _ := vars["caName"]

	caTypeString, _ := vars["caType"]

	caType, err := dto.ParseCAType(caTypeString)
	if err != nil {
		return nil, InvalidCaType()
	}
	serialNumber, _ := vars["serialNumber"]

	return endpoint.GetCertRequest{
		CaType:       caType,
		CaName:       caName,
		SerialNumber: serialNumber,
	}, nil
}

func decodeSignCertificateRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	caName, _ := vars["caName"]

	caType, _ := vars["caType"]

	var signRequest endpoint.SignCertificateRquest

	err = json.NewDecoder(r.Body).Decode(&signRequest.SignPayload)
	if err != nil {
		return nil, InvalidJsonFormat()
	}

	signRequest.CaName = caName
	signRequest.CaType = caType

	return signRequest, nil
}

func decodeDeleteCertRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	ca, _ := vars["caName"]

	caTypeString, _ := vars["caType"]

	caType, err := dto.ParseCAType(caTypeString)
	if err != nil {
		return nil, InvalidCaType()
	}

	serialNumber, _ := vars["serialNumber"]

	return endpoint.DeleteCertRequest{
		CaType:       caType,
		CaName:       ca,
		SerialNumber: serialNumber,
	}, nil
}

func encodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
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
func filterQuery(r *http.Request) dto.QueryParameters {
	f := ""
	orderArray := ""
	pageArray := ""
	page := ""
	offset := ""
	field := ""
	order := ""

	helper, _ := url.QueryUnescape(r.URL.RawQuery)

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
func removeAmpersand(helper string) string {
	if strings.HasPrefix(helper, "&") {
		helper = strings.TrimPrefix(helper, "&")
	}
	return helper
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
