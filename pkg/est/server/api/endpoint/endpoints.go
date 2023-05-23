package endpoint

import (
	"context"
	"crypto/rsa"
	"crypto/x509"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-playground/validator/v10"
	esterror "github.com/lamassuiot/lamassuiot/pkg/est/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/est/server/api/service"
)

type Endpoints struct {
	HealthEndpoint       endpoint.Endpoint
	GetCAsEndpoint       endpoint.Endpoint
	EnrollerEndpoint     endpoint.Endpoint
	ReenrollerEndpoint   endpoint.Endpoint
	ServerKeyGenEndpoint endpoint.Endpoint
}

func MakeServerEndpoints(s service.ESTService) Endpoints {
	var healthEndpoint = MakeHealthEndpoint(s)
	var getCasEndpoint = MakeGetCAsEndpoint(s)
	var enrollEndpoint = MakeEnrollEndpoint(s)
	var reenrollEndpoint = MakeReenrollEndpoint(s)
	var serverkeygenEndpoint = MakeServerKeyGenEndpoint(s)

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
		req := request.(CACertsRequest)
		cas, err := s.CACerts(ctx, req.Aps)
		return GetCasResponse{Certs: cas, PemResponse: req.PemResponse}, err
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

		ctx = context.WithValue(ctx, "dmsName", req.DmsName)
		crt, err := s.Enroll(ctx, req.Csr, req.Crt, req.Aps)
		return EnrollReenrollResponse{Cert: crt, PemResponse: req.PemResponse}, err
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
		crt, err := s.Reenroll(ctx, req.Csr, req.Crt, req.Aps)
		return EnrollReenrollResponse{Cert: crt, PemResponse: req.PemResponse}, err
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
		ctx = context.WithValue(ctx, "dmsName", req.DmsName)
		crt, key, err := s.ServerKeyGen(ctx, req.Csr, req.Crt, req.Aps)
		return ServerKeyGenResponse{Cert: crt, Key: key}, err
	}
}

type EmptyRequest struct{}

type EnrollRequest struct {
	Aps         string                   `validate:"required"`
	Csr         *x509.CertificateRequest `validate:"required"`
	Crt         *x509.Certificate        `validate:"required"`
	DmsName     string
	PemResponse bool
}

type CACertsRequest struct {
	Aps         string
	PemResponse bool
}

func ValidatetEnrollRequest(request EnrollRequest) error {
	validate := validator.New()
	return validate.Struct(request)
}

type ReenrollRequest struct {
	Aps         string
	Csr         *x509.CertificateRequest `validate:"required"`
	Crt         *x509.Certificate        `validate:"required"`
	PemResponse bool
}

func ValidatetReenrollRequest(request ReenrollRequest) error {
	validate := validator.New()
	return validate.Struct(request)
}

type ServerKeyGenRequest struct {
	Csr     *x509.CertificateRequest `validate:"required"`
	Aps     string                   `validate:"required"`
	Crt     *x509.Certificate        `validate:"required"`
	DmsName string
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
	Certs       []*x509.Certificate
	PemResponse bool
}

type EnrollReenrollResponse struct {
	Cert        *x509.Certificate
	CaCert      *x509.Certificate
	PemResponse bool
}
type ServerKeyGenResponse struct {
	Cert   *x509.Certificate
	Key    *rsa.PrivateKey
	CaCert *x509.Certificate
}
