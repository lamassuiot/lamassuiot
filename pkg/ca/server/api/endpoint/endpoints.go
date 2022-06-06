package endpoint

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/tracing/opentracing"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type Endpoints struct {
	HealthEndpoint         endpoint.Endpoint
	StatsEndpoint          endpoint.Endpoint
	GetCAsEndpoint         endpoint.Endpoint
	CreateCAEndpoint       endpoint.Endpoint
	ImportCAEndpoint       endpoint.Endpoint
	DeleteCAEndpoint       endpoint.Endpoint
	GetIssuedCertsEndpoint endpoint.Endpoint
	GetCertEndpoint        endpoint.Endpoint
	SignCertEndpoint       endpoint.Endpoint
	DeleteCertEndpoint     endpoint.Endpoint
}

func MakeServerEndpoints(s service.Service, otTracer stdopentracing.Tracer) Endpoints {
	var healthEndpoint endpoint.Endpoint
	{
		healthEndpoint = MakeHealthEndpoint(s)
		healthEndpoint = opentracing.TraceServer(otTracer, "Health")(healthEndpoint)
	}

	var statsEndpoint endpoint.Endpoint
	{
		statsEndpoint = MakeStatsEndpoint(s)
		statsEndpoint = opentracing.TraceServer(otTracer, "Stats")(statsEndpoint)
	}

	var getCAsEndpoint endpoint.Endpoint
	{
		getCAsEndpoint = MakeGetCAsEndpoint(s)
		getCAsEndpoint = opentracing.TraceServer(otTracer, "GetCAs")(getCAsEndpoint)
	}

	var createCAEndpoint endpoint.Endpoint
	{
		createCAEndpoint = MakeCreateCAEndpoint(s)
		createCAEndpoint = opentracing.TraceServer(otTracer, "CreateCA")(createCAEndpoint)
	}

	var importCAEndpoint endpoint.Endpoint
	{
		importCAEndpoint = MakeImportCAEndpoint(s)
		importCAEndpoint = opentracing.TraceServer(otTracer, "ImportCA")(importCAEndpoint)
	}

	var deleteCAEndpoint endpoint.Endpoint
	{
		deleteCAEndpoint = MakeDeleteCAEndpoint(s)
		deleteCAEndpoint = opentracing.TraceServer(otTracer, "DeleteCA")(deleteCAEndpoint)
	}

	var getIssuedCertsEndpoint endpoint.Endpoint
	{
		getIssuedCertsEndpoint = MakeIssuedCertsEndpoint(s)
		getIssuedCertsEndpoint = opentracing.TraceServer(otTracer, "GetIssuedCerts")(getIssuedCertsEndpoint)
	}
	var getCertEndpoint endpoint.Endpoint
	{
		getCertEndpoint = MakeCertEndpoint(s)
		getCertEndpoint = opentracing.TraceServer(otTracer, "GetCert")(getCertEndpoint)
	}

	var signCertificateEndpoint endpoint.Endpoint
	{
		signCertificateEndpoint = MakeSignCertEndpoint(s)
		signCertificateEndpoint = opentracing.TraceServer(otTracer, "SignCertificate")(signCertificateEndpoint)
	}

	var deleteCertEndpoint endpoint.Endpoint
	{
		deleteCertEndpoint = MakeDeleteCertEndpoint(s)
		deleteCertEndpoint = opentracing.TraceServer(otTracer, "DeleteCert")(deleteCertEndpoint)
	}

	return Endpoints{
		HealthEndpoint:         healthEndpoint,
		StatsEndpoint:          statsEndpoint,
		GetCAsEndpoint:         getCAsEndpoint,
		CreateCAEndpoint:       createCAEndpoint,
		ImportCAEndpoint:       importCAEndpoint,
		DeleteCAEndpoint:       deleteCAEndpoint,
		GetIssuedCertsEndpoint: getIssuedCertsEndpoint,
		GetCertEndpoint:        getCertEndpoint,
		DeleteCertEndpoint:     deleteCertEndpoint,
		SignCertEndpoint:       signCertificateEndpoint,
	}
}

func MakeHealthEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		healthy := s.Health(ctx)
		return HealthResponse{Healthy: healthy}, nil
	}
}

func MakeStatsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		stats := s.Stats(ctx)
		return stats, nil
	}
}

func MakeGetCAsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(GetCAsRequest)

		caType, _ := dto.ParseCAType(req.CaType)

		cas, totalcas, err := s.GetCAs(ctx, caType, req.QueryParameters)
		return dto.GetCasResponse{TotalCas: totalcas, CAs: cas}, err
	}
}

func MakeCreateCAEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(CreateCARequest)

		err = ValidateCreatrCARequest(req)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		caType, _ := dto.ParseCAType(req.CaType)

		ca, err := s.CreateCA(ctx, caType, req.CaName, dto.PrivateKeyMetadata(req.CaPayload.KeyMetadata), dto.Subject(req.CaPayload.Subject), req.CaPayload.CaTTL, req.CaPayload.EnrollerTTL)
		return ca, err
	}
}

func MakeDeleteCAEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(DeleteCARequest)

		issuedCerts, _, err := s.GetIssuedCerts(ctx, req.CaType, req.CA, filters.QueryParameters{})
		if err != nil {
			return nil, err
		}

		for _, issuedCert := range issuedCerts {
			if issuedCert.Status != "revoked" {
				s.DeleteCert(ctx, req.CaType, req.CA, issuedCert.SerialNumber)
			}
		}

		err = s.DeleteCA(ctx, req.CaType, req.CA)
		return nil, err
	}
}

func MakeImportCAEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(ImportCARequest)

		err = ValidateImportCARequest(req)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		caType, _ := dto.ParseCAType(req.CaType)

		data, _ := base64.StdEncoding.DecodeString(req.CaPayload.Crt)
		block, _ := pem.Decode([]byte(data))
		crt, _ := x509.ParseCertificate(block.Bytes)

		privKey := dto.PrivateKey{}

		privKeyData, _ := base64.StdEncoding.DecodeString(req.CaPayload.PrivateKey)
		privKeyBlock, _ := pem.Decode([]byte(privKeyData))
		ecdsaKey, err := x509.ParseECPrivateKey(privKeyBlock.Bytes)

		if err == nil {
			privKey.Key = ecdsaKey
		} else {
			rsaKey, err := x509.ParsePKCS8PrivateKey(privKeyBlock.Bytes)
			if err == nil {
				privKey.Key = rsaKey
			} else {
				err = &errors.GenericError{
					Message:    "Invalid Key bits",
					StatusCode: 400,
				}
				return nil, err
			}
		}

		ca, err := s.ImportCA(ctx, caType, req.CaName, *crt, privKey, req.CaPayload.EnrollerTTL)
		return ca, err
	}
}

func MakeIssuedCertsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(GetIssuedCertsRequest)
		certs, length, err := s.GetIssuedCerts(ctx, req.CaType, req.CA, req.QueryParameters)
		return dto.IssuedCertsResponse{TotalCerts: length, Certs: certs}, err
	}
}

func MakeCertEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(GetCertRequest)
		cert, err := s.GetCert(ctx, req.CaType, req.CaName, req.SerialNumber)
		return cert, err
	}
}

func MakeSignCertEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(SignCertificateRquest)

		err = ValidateSignCertificateRquest(req)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		data, _ := base64.StdEncoding.DecodeString(req.SignPayload.Csr)
		block, _ := pem.Decode([]byte(data))
		csr, _ := x509.ParseCertificateRequest(block.Bytes)

		caType, _ := dto.ParseCAType(req.CaType)

		certs, err := s.SignCertificate(ctx, caType, req.CaName, *csr, req.SignPayload.SignVerbatim, req.SignPayload.CommonName)
		return certs, err
	}
}

func MakeDeleteCertEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(DeleteCertRequest)
		err = s.DeleteCert(ctx, req.CaType, req.CaName, req.SerialNumber)
		if err != nil {
			return "", err
		} else {
			return "OK", err
		}
	}
}

type HealthRequest struct{}

type HealthResponse struct {
	Healthy bool  `json:"healthy,omitempty"`
	Err     error `json:"-"`
}

func ValidateCreatrCARequest(request CreateCARequest) error {
	CreateCARequestStructLevelValidation := func(sl validator.StructLevel) {
		req := sl.Current().Interface().(CreateCARequest)
		switch req.CaPayload.KeyMetadata.KeyType {
		case "RSA":
			if math.Mod(float64(req.CaPayload.KeyMetadata.KeyBits), 1024) != 0 || req.CaPayload.KeyMetadata.KeyBits < 2048 {
				sl.ReportError(req.CaPayload.KeyMetadata.KeyBits, "bits", "Bits", "bits1024multipleAndGt2048", "")
			}
		case "EC":
			if req.CaPayload.KeyMetadata.KeyBits != 224 && req.CaPayload.KeyMetadata.KeyBits != 256 && req.CaPayload.KeyMetadata.KeyBits != 384 {
				sl.ReportError(req.CaPayload.KeyMetadata.KeyBits, "bits", "Bits", "bitsEcdsaMultiple", "")
			}
		}

		if req.CaPayload.EnrollerTTL >= req.CaPayload.CaTTL {
			sl.ReportError(req.CaPayload.EnrollerTTL, "enrollerttl", "EnrollerTTL", "enrollerTtlGtCaTtl", "")
		}

		if req.CaPayload.Subject.CommonName != req.CaName {
			sl.ReportError(req.CaPayload.Subject.CommonName, "commonName", "CommonName", "commonName and caName must be equal", "")
		}
	}

	validate := validator.New()
	validate.RegisterStructValidation(CreateCARequestStructLevelValidation, CreateCARequest{})
	return validate.Struct(request)
}

func ValidateImportCARequest(request ImportCARequest) error {
	validate := validator.New()
	return validate.Struct(request)
}

func ValidateSignCertificateRquest(request SignCertificateRquest) error {
	validate := validator.New()
	return validate.Struct(request)
}

type StatsRequest struct {
	ForceRefesh bool
}

type GetCAsRequest struct {
	CaType          string
	QueryParameters filters.QueryParameters
}

type CaRequest struct {
	CaType dto.CAType
	CA     string
}
type GetIssuedCertsRequest struct {
	CaType          dto.CAType
	CA              string
	QueryParameters filters.QueryParameters
}
type DeleteCARequest struct {
	CaType dto.CAType
	CA     string
}

type GetCertRequest struct {
	CaType       dto.CAType
	CaName       string
	SerialNumber string
}
type DeleteCertRequest struct {
	CaName       string
	SerialNumber string
	CaType       dto.CAType
}
type CreateCARequest struct {
	CaType    string `validate:"oneof='pki' 'dmsenroller'"`
	CaName    string `validate:"required"`
	CaPayload dto.CreateCARequestPayload
}
type ImportCARequest struct {
	CaType    string `validate:"oneof='pki' 'dmsenroller'"`
	CaName    string `validate:"required"`
	CaPayload dto.ImportCARequestPayload
}
type SignCertificateRquest struct {
	CaType      string `validate:"oneof='pki' 'dmsenroller'"`
	CaName      string `validate:"required"`
	SignPayload dto.SignPayload
}
