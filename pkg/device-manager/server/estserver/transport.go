package estserver

import (
	"context"
	"net/http"

	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/go-kit/log"
	"github.com/gorilla/mux"
	lamassuca "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/configs"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/estserver/mtls"
	estEndpoint "github.com/lamassuiot/lamassuiot/pkg/est/server/api/endpoint"
	estService "github.com/lamassuiot/lamassuiot/pkg/est/server/api/service"
	esttransport "github.com/lamassuiot/lamassuiot/pkg/est/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	stdopentracing "github.com/opentracing/opentracing-go"
)

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

func MakeHTTPHandler(service estService.Service, lamassuCaClient *lamassuca.LamassuCaClient, logger log.Logger, cfg configs.Config, otTracer stdopentracing.Tracer, ctx context.Context) http.Handler {
	router := mux.NewRouter()
	endpoints := estEndpoint.MakeServerEndpoints(service, otTracer)
	CaClient := *lamassuCaClient
	options := []httptransport.ServerOption{
		httptransport.ServerBefore(HTTPToContext(logger)),
		httptransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		httptransport.ServerErrorEncoder(esttransport.EncodeError),
		httptransport.ServerBefore(mtls.HTTPToContext()),
	}

	// MUST as per rfc7030
	router.Methods("GET").Path("/.well-known/est/cacerts").Handler(httptransport.NewServer(
		endpoints.GetCAsEndpoint,
		esttransport.DecodeRequest,
		esttransport.EncodeGetCaCertsResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "cacerts", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	router.Methods("POST").Path("/.well-known/est/{aps}/simpleenroll").Handler(httptransport.NewServer(
		mtls.NewParser(true, cfg.MutualTLSClientCA, CaClient, ctx)(endpoints.EnrollerEndpoint),
		esttransport.DecodeEnrollRequest,
		esttransport.EncodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "simpleenroll", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	router.Methods("POST").Path("/.well-known/est/simplereenroll").Handler(httptransport.NewServer(
		mtls.NewParser(false, cfg.MutualTLSClientCA, CaClient, ctx)(endpoints.ReenrollerEndpoint),
		esttransport.DecodeReenrollRequest,
		esttransport.EncodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "simplereenroll", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))
	router.Methods("POST").Path("/.well-known/est/{aps}/serverkeygen").Handler(httptransport.NewServer(
		mtls.NewParser(true, cfg.MutualTLSClientCA, CaClient, ctx)(endpoints.ServerKeyGenEndpoint),
		esttransport.DecodeServerkeygenRequest,
		esttransport.EncodeServerkeygenResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "serverkeygen", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	return router
}
