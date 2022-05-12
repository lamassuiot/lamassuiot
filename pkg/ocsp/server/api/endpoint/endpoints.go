package endpoints

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/lamassuiot/lamassuiot/pkg/ocsp/server/api/service"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type Endpoints struct {
	GetEndpoint    endpoint.Endpoint
	PostEndpoint   endpoint.Endpoint
	HealthEndpoint endpoint.Endpoint
}

func MakeServerEndpoints(s service.Service, otTracer stdopentracing.Tracer) Endpoints {
	var healthEndpoint endpoint.Endpoint
	{
		healthEndpoint = MakeHealthEndpoint(s)
		healthEndpoint = opentracing.TraceServer(otTracer, "Health")(healthEndpoint)
	}
	var getEndpoint endpoint.Endpoint
	{
		getEndpoint = MakeOCSPEndpoint(s)
		getEndpoint = opentracing.TraceServer(otTracer, "GetOCSPOperation")(getEndpoint)
	}
	var postEndpoint endpoint.Endpoint
	{
		postEndpoint = MakeOCSPEndpoint(s)
		postEndpoint = opentracing.TraceServer(otTracer, "PostOCSPOperation")(postEndpoint)
	}
	return Endpoints{
		GetEndpoint:    getEndpoint,
		PostEndpoint:   postEndpoint,
		HealthEndpoint: healthEndpoint,
	}
}

func MakeOCSPEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(OcspRequest)
		resp, err := s.Verify(ctx, req.Msg)
		return OcspResponse{Resp: resp, Err: err}, nil
	}
}

func MakeHealthEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		healthy := s.Health(ctx)
		return HealthResponse{Healthy: healthy}, nil
	}
}

type HealthRequest struct{}

type HealthResponse struct {
	Healthy bool  `json:"healthy,omitempty"`
	Err     error `json:"err,omitempty"`
}

type OcspRequest struct {
	Msg []byte
}

type OcspResponse struct {
	Resp []byte
	Err  error
}

func (r OcspResponse) error() error { return r.Err }
