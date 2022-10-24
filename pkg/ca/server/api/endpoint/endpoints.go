package endpoint

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/tracing/opentracing"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type Endpoints struct {
	HealthEndpoint          endpoint.Endpoint
	GetCryptoEngine         endpoint.Endpoint
	StatsEndpoint           endpoint.Endpoint
	GetCAsEndpoint          endpoint.Endpoint
	GetCAByNameEndpoint     endpoint.Endpoint
	CreateCAEndpoint        endpoint.Endpoint
	ImportCAEndpoint        endpoint.Endpoint
	RevokeCAEndpoint        endpoint.Endpoint
	GetCertificatesEndpoint endpoint.Endpoint
	GetCertEndpoint         endpoint.Endpoint
	SignCertEndpoint        endpoint.Endpoint
	RevokeCertEndpoint      endpoint.Endpoint
}

func MakeServerEndpoints(s service.Service, otTracer stdopentracing.Tracer) Endpoints {
	var healthEndpoint endpoint.Endpoint
	{
		healthEndpoint = MakeHealthEndpoint(s)
		healthEndpoint = opentracing.TraceServer(otTracer, "Health")(healthEndpoint)
	}
	var getCryptoEngineEndpoint endpoint.Endpoint
	{
		getCryptoEngineEndpoint = MakeGetCryptoEngine(s)
		getCryptoEngineEndpoint = opentracing.TraceServer(otTracer, "CryptoEngine")(getCryptoEngineEndpoint)
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

	var getCAByName endpoint.Endpoint
	{
		getCAByName = MakeGetCAByNameEndpoint(s)
		getCAByName = opentracing.TraceServer(otTracer, "GetCAByName")(getCAByName)
	}

	var createCAEndpoint endpoint.Endpoint
	{
		createCAEndpoint = MakeCreateCAEndpoint(s)
		createCAEndpoint = opentracing.TraceServer(otTracer, "CreateCA")(createCAEndpoint)
	}

	// var importCAEndpoint endpoint.Endpoint
	// {
	// 	importCAEndpoint = MakeImportCAEndpoint(s)
	// 	importCAEndpoint = opentracing.TraceServer(otTracer, "ImportCA")(importCAEndpoint)
	// }

	var revokeCAEndpoint endpoint.Endpoint
	{
		revokeCAEndpoint = MakeRevokeCAEndpoint(s)
		revokeCAEndpoint = opentracing.TraceServer(otTracer, "RevokeCA")(revokeCAEndpoint)
	}

	var getGetCertificatesEndpoint endpoint.Endpoint
	{
		getGetCertificatesEndpoint = MakeGetCertificatesEndpoint(s)
		getGetCertificatesEndpoint = opentracing.TraceServer(otTracer, "GetGetCertificates")(getGetCertificatesEndpoint)
	}
	var getCertEndpoint endpoint.Endpoint
	{
		getCertEndpoint = MakeCertEndpoint(s)
		getCertEndpoint = opentracing.TraceServer(otTracer, "GetCertificate")(getCertEndpoint)
	}

	var signCertificateEndpoint endpoint.Endpoint
	{
		signCertificateEndpoint = MakeSignCertEndpoint(s)
		signCertificateEndpoint = opentracing.TraceServer(otTracer, "SignCertificate")(signCertificateEndpoint)
	}

	var revokeCertEndpoint endpoint.Endpoint
	{
		revokeCertEndpoint = MakeRevokeCertEndpoint(s)
		revokeCertEndpoint = opentracing.TraceServer(otTracer, "RevokeCertificate")(revokeCertEndpoint)
	}

	return Endpoints{
		HealthEndpoint:          healthEndpoint,
		GetCryptoEngine:         getCryptoEngineEndpoint,
		StatsEndpoint:           statsEndpoint,
		GetCAsEndpoint:          getCAsEndpoint,
		GetCAByNameEndpoint:     getCAByName,
		CreateCAEndpoint:        createCAEndpoint,
		RevokeCAEndpoint:        revokeCAEndpoint,
		GetCertificatesEndpoint: getGetCertificatesEndpoint,
		GetCertEndpoint:         getCertEndpoint,
		RevokeCertEndpoint:      revokeCertEndpoint,
		SignCertEndpoint:        signCertificateEndpoint,
		// ImportCAEndpoint:       importCAEndpoint,
	}
}

func MakeHealthEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		healthy := s.Health()
		return HealthResponse{Healthy: healthy}, nil
	}
}

func MakeStatsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetStatsInput)
		stats, err := s.Stats(ctx, &input)
		return stats, err
	}
}

func MakeGetCryptoEngine(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		engineInfo := s.GetEngineProviderInfo()
		return engineInfo, nil
	}
}

func MakeGetCAsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetCAsInput)
		output, err := s.GetCAs(ctx, &input)
		return output, err
	}
}

func MakeGetCAByNameEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetCAByNameInput)
		output, err := s.GetCAByName(ctx, &input)
		return output, err
	}
}

func MakeCreateCAEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.CreateCAInput)
		ca, err := s.CreateCA(ctx, &input)
		return ca, err
	}
}

func MakeRevokeCAEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.RevokeCAInput)
		output, err := s.RevokeCA(ctx, &input)
		return output, err
	}
}

// func MakeImportCAEndpoint(s service.Service) endpoint.Endpoint {
// 	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
// 		req := request.(api.ImportCAInput)
// 		ca, err := s.ImportCA(ctx, caType, req.CaName, *crt, privKey, req.CaPayload.EnrollerTTL)
// 		return ca, err
// 	}
// }

func MakeGetCertificatesEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetCertificatesInput)
		output, err := s.GetCertificates(ctx, &input)
		return output, err
	}
}

func MakeCertEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetCertificateBySerialNumberInput)
		output, err := s.GetCertificateBySerialNumber(ctx, &input)
		return output, err
	}
}

func MakeSignCertEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.SignCertificateRequestInput)
		output, err := s.SignCertificateRequest(ctx, &input)
		return output, err
	}
}

func MakeRevokeCertEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.RevokeCertificateInput)
		output, err := s.RevokeCertificate(ctx, &input)
		return output, err
	}
}

type HealthResponse struct {
	Healthy bool `json:"healthy,omitempty"`
}
