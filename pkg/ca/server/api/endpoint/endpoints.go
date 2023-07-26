package endpoint

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"

	"github.com/go-kit/kit/endpoint"
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
	SignEndpoint            endpoint.Endpoint
	VerifyEndpoint          endpoint.Endpoint
}

func MakeServerEndpoints(s service.Service) Endpoints {
	var healthEndpoint = MakeHealthEndpoint(s)
	var getCryptoEngineEndpoint = MakeGetCryptoEngine(s)
	var statsEndpoint = MakeStatsEndpoint(s)
	var getCAsEndpoint = MakeGetCAsEndpoint(s)
	var getCAByName = MakeGetCAByNameEndpoint(s)
	var createCAEndpoint = MakeCreateCAEndpoint(s)
	var importCAEndpoint = MakeImportCAEndpoint(s)

	// var importCAEndpoint endpoint.Endpoint
	// {
	// 	importCAEndpoint = MakeImportCAEndpoint(s)
	// 	importCAEndpoint = opentracing.TraceServer(otTracer, "ImportCA")(importCAEndpoint)
	// }

	var revokeCAEndpoint = MakeRevokeCAEndpoint(s)
	var getGetCertificatesEndpoint = MakeGetCertificatesEndpoint(s)
	var getCertEndpoint = MakeCertEndpoint(s)
	var signCertificateEndpoint = MakeSignCertEndpoint(s)
	var revokeCertEndpoint = MakeRevokeCertEndpoint(s)
	var signEndpoint = MakeSignEndpoint(s)
	var verifyEndpoint = MakeVerifyEndpoint(s)

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
		SignEndpoint:            signEndpoint,
		VerifyEndpoint:          verifyEndpoint,
		ImportCAEndpoint:        importCAEndpoint,
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

func MakeImportCAEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(api.ImportCAInput)
		output, err := s.ImportCA(ctx, &req)
		return output, err
	}
}

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

func MakeSignEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.SignInput)
		output, err := s.Sign(ctx, &input)
		return output, err
	}
}

func MakeVerifyEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.VerifyInput)
		output, err := s.Verify(ctx, &input)
		return output, err
	}
}

type HealthResponse struct {
	Healthy bool `json:"healthy,omitempty"`
}
