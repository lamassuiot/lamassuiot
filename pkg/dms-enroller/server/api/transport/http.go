package transport

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/api/endpoint"
	dmsErrors "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/utils"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"

	stdopentracing "github.com/opentracing/opentracing-go"
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
		httptransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		httptransport.ServerErrorEncoder(encodeError),
		// httptransport.ServerBefore(jwt.HTTPToContext()),
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

	r.Methods("POST").Path("/v1/{name}").Handler(httptransport.NewServer(
		e.PostCreateDMSEndpoint,
		decodePostCSRRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "PostCSR", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))
	r.Methods("POST").Path("/v1/{name}/form").Handler(httptransport.NewServer(
		e.PostCreateDMSFormEndpoint,
		decodePostCreateDMSFormRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "PostCSRForm", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("GET").Path("/v1/").Handler(httptransport.NewServer(
		e.GetDMSsEndpoint,
		decodeGetDMSsRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetPendingCSRs", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))
	r.Methods("GET").Path("/v1/{id}").Handler(httptransport.NewServer(
		e.GetDMSbyIDEndpoint,
		decodeGetDMSbyIDRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetDMSbyID", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))
	r.Methods("PUT").Path("/v1/{id}").Handler(httptransport.NewServer(
		e.PutChangeDMSStatusEndpoint,
		decodeputChangeDmsStatusRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "PutChangeCSRStatus", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	r.Methods("DELETE").Path("/v1/{id}").Handler(httptransport.NewServer(
		e.DeleteDMSEndpoint,
		decodeDeleteCSRRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "DeleteCSR", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	return r
}

type PostDmsResponse struct {
	Dms dto.DMS `json:"dms,omitempty"`
	Err error   `json:"err,omitempty"`
}
type PostDmsCreationFormResponse struct {
	Dms     dto.DMS `json:"dms,omitempty"`
	PrivKey string  `json:"priv_key,omitempty"`
	Err     error   `json:"err,omitempty"`
}

type GetCRTResponse struct {
	Data *x509.Certificate
	Err  error
}

func decodeHealthRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var req endpoint.HealthRequest
	return req, nil
}

func decodeGetDMSsRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var req endpoint.GetDmsRequest
	return req, nil
}
func decodeGetDMSbyIDRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	id, _ := vars["id"]
	return endpoint.GetDmsIDRequest{ID: id}, nil
}
func decodePostCreateDMSFormRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	name, _ := vars["name"]
	var dmsForm dto.PostDmsCreationFormRequest
	err = json.NewDecoder(r.Body).Decode((&dmsForm))
	if err != nil {
		return nil, InvalidJsonFormat()
	}
	dmsForm.DmsName = name
	return dmsForm, nil
}

func decodePostCSRRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)

	var csrRequest endpoint.PostDirectCsr
	err = json.NewDecoder(r.Body).Decode((&csrRequest))
	if err != nil {
		return nil, InvalidJsonFormat()
	}
	name, _ := vars["name"]

	req := dto.PostCSRRequest{
		Csr:     csrRequest.CsrBase64Encoded,
		DmsName: name,
	}
	return req, nil
}

func decodeputChangeDmsStatusRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	id, _ := vars["id"]
	var Request dto.PutChangeDmsStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&Request); err != nil {
		return nil, InvalidJsonFormat()
	}
	if Request.Status == "" {
		return nil, ErrMissingDMSStatus()
	}

	Request.ID = id
	return Request, nil

}

func decodeDeleteCSRRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	id, _ := vars["id"]
	return endpoint.DeleteCSRRequest{ID: id}, nil
}

func encodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
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
