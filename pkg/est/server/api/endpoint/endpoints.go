package endpoint

import (
	"context"
	"crypto/x509"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-playground/validator/v10"
	esterror "github.com/lamassuiot/lamassuiot/pkg/est/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/est/server/api/service"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type Endpoints struct {
	HealthEndpoint       endpoint.Endpoint
	GetCAsEndpoint       endpoint.Endpoint
	EnrollerEndpoint     endpoint.Endpoint
	ReenrollerEndpoint   endpoint.Endpoint
	ServerKeyGenEndpoint endpoint.Endpoint
}

func MakeServerEndpoints(s service.ESTService, otTracer stdopentracing.Tracer) Endpoints {
	var healthEndpoint endpoint.Endpoint
	{
		healthEndpoint = MakeHealthEndpoint(s)
		healthEndpoint = opentracing.TraceServer(otTracer, "Health")(healthEndpoint)
	}

	var getCasEndpoint endpoint.Endpoint
	{
		getCasEndpoint = MakeGetCAsEndpoint(s)
		getCasEndpoint = opentracing.TraceServer(otTracer, "GetCAs")(getCasEndpoint)
	}

	var enrollEndpoint endpoint.Endpoint
	{
		enrollEndpoint = MakeEnrollEndpoint(s)
		enrollEndpoint = opentracing.TraceServer(otTracer, "Enroll")(enrollEndpoint)
	}

	var reenrollEndpoint endpoint.Endpoint
	{
		reenrollEndpoint = MakeReenrollEndpoint(s)
		reenrollEndpoint = opentracing.TraceServer(otTracer, "Reenroll")(reenrollEndpoint)
	}
	var serverkeygenEndpoint endpoint.Endpoint
	{
		serverkeygenEndpoint = MakeServerKeyGenEndpoint(s)
		serverkeygenEndpoint = opentracing.TraceServer(otTracer, "Serverkeygen")(serverkeygenEndpoint)
	}
	return Endpoints{
		HealthEndpoint:       healthEndpoint,
		GetCAsEndpoint:       getCasEndpoint,
		EnrollerEndpoint:     enrollEndpoint,
		ReenrollerEndpoint:   reenrollEndpoint,
		ServerKeyGenEndpoint: serverkeygenEndpoint,
	}
}

func MakeHealthEndpoint(s service.ESTService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		healthy := s.Health(ctx)
		return HealthResponse{Healthy: healthy}, nil
	}
}

func MakeGetCAsEndpoint(s service.ESTService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		cas, err := s.CACerts(ctx, "")
		return GetCasResponse{Certs: cas}, err
	}
}

func MakeEnrollEndpoint(s service.ESTService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(EnrollRequest)
		err = ValidatetEnrollRequest(req)
		if err != nil {
			valError := esterror.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}
		crt, err := s.Enroll(ctx, req.Csr, req.Aps, req.Crt)
		return EnrollReenrollResponse{Cert: crt}, err
	}
}

func MakeReenrollEndpoint(s service.ESTService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(ReenrollRequest)
		err = ValidatetReenrollRequest(req)
		if err != nil {
			valError := esterror.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}
		crt, err := s.Reenroll(ctx, req.Crt, req.Csr, "")
		return EnrollReenrollResponse{Cert: crt}, err
	}
}

func MakeServerKeyGenEndpoint(s service.ESTService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(ServerKeyGenRequest)
		err = ValidateServerKeyGenRequest(req)
		if err != nil {
			valError := esterror.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}
		crt, key, err := s.ServerKeyGen(ctx, req.Csr, req.Aps, req.Crt)
		return ServerKeyGenResponse{Cert: crt, Key: key}, err
	}
}

type EmptyRequest struct{}

type EnrollRequest struct {
	Csr *x509.CertificateRequest `validate:"required"`
	Aps string                   `validate:"required"`
	Crt *x509.Certificate        `validate:"required"`
}

func ValidatetEnrollRequest(request EnrollRequest) error {
	validate := validator.New()
	return validate.Struct(request)
}

type ReenrollRequest struct {
	Csr *x509.CertificateRequest `validate:"required"`
	Crt *x509.Certificate        `validate:"required"`
}

func ValidatetReenrollRequest(request ReenrollRequest) error {
	validate := validator.New()
	return validate.Struct(request)
}

type ServerKeyGenRequest struct {
	Csr *x509.CertificateRequest `validate:"required"`
	Aps string                   `validate:"required"`
	Crt *x509.Certificate        `validate:"required"`
}

func ValidateServerKeyGenRequest(request ServerKeyGenRequest) error {
	validate := validator.New()
	return validate.Struct(request)
}

type HealthResponse struct {
	Healthy bool  `json:"healthy,omitempty"`
	Err     error `json:"err,omitempty"`
}

type GetCasResponse struct {
	Certs []*x509.Certificate
}
type EnrollReenrollResponse struct {
	Cert   *x509.Certificate
	CaCert *x509.Certificate
}
type ServerKeyGenResponse struct {
	Cert   *x509.Certificate
	Key    []byte
	CaCert *x509.Certificate
}
