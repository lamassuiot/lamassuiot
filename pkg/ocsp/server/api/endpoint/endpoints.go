package endpoints

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/lamassuiot/lamassuiot/pkg/ocsp/server/api/service"
)

type Endpoints struct {
	GetEndpoint    endpoint.Endpoint
	PostEndpoint   endpoint.Endpoint
	HealthEndpoint endpoint.Endpoint
}

func MakeServerEndpoints(s service.Service) Endpoints {
	var healthEndpoint = MakeHealthEndpoint(s)
	var getEndpoint = MakeOCSPEndpoint(s)
	var postEndpoint = MakeOCSPEndpoint(s)

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
