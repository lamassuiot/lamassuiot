package endpoint

import (
	"context"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/errors"
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

func ValidateStatsRequest(request api.GetStatsInput) error {
	GetStatsRequestStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetStatsInput)
	}

	validate := validator.New()
	validate.RegisterStructValidation(GetStatsRequestStructLevelValidation, api.CreateCAInput{})
	return validate.Struct(request)
}

func MakeStatsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetStatsInput)

		err = ValidateStatsRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

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

func ValidateGetCAsRequest(request api.GetCAsInput) error {
	GetCAsRequestStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetCAsInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(GetCAsRequestStructLevelValidation, api.GetCAsInput{})
	return validate.Struct(request)
}

func MakeGetCAsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetCAsInput)

		err = ValidateGetCAsRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.GetCAs(ctx, &input)
		return output, err
	}
}

func ValidateGetCAByNameRequest(request api.GetCAByNameInput) error {
	GetCAByNameRequestStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetCAByNameInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(GetCAByNameRequestStructLevelValidation, api.GetCAByNameInput{})
	return validate.Struct(request)
}

func MakeGetCAByNameEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetCAByNameInput)

		err = ValidateGetCAByNameRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.GetCAByName(ctx, &input)
		return output, err
	}
}

func ValidateCreateCARequest(request api.CreateCAInput) error {
	CreateCARequestStructLevelValidation := func(sl validator.StructLevel) {
		input := sl.Current().Interface().(api.CreateCAInput)

		if input.Subject.CommonName == "" {
			sl.ReportError(input.Subject.CommonName, "CommonName", "CommonName", "CommonNameIsEmpty", "")
		}

		if input.KeyMetadata.KeyType == api.RSA {
			if input.KeyMetadata.KeyBits%1024 != 0 || input.KeyMetadata.KeyBits == 0 {
				sl.ReportError(input.KeyMetadata.KeyBits, "KeyBits", "KeyBits", "InvalidRSAKeyBits", "")
			}
		}

		if input.IssuanceDuration.Seconds() <= 0 {
			sl.ReportError(input.IssuanceDuration, "IssuanceDuration", "IssuanceDuration", "MissingIssuanceDuration", "")
		}

		if input.CADuration.Seconds() <= 0 {
			sl.ReportError(input.CADuration, "CADuration", "CADuration", "MissingCADuration", "")
		}

		if input.IssuanceDuration >= input.CADuration {
			sl.ReportError(input.IssuanceDuration, "IssuanceDuration", "IssuanceDuration", "IssuanceDurationGreaterThanCADuration", "")
		}
	}

	validate := validator.New()
	validate.RegisterStructValidation(CreateCARequestStructLevelValidation, api.CreateCAInput{})
	return validate.Struct(request)
}

func MakeCreateCAEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.CreateCAInput)

		err = ValidateCreateCARequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		ca, err := s.CreateCA(ctx, &input)
		return ca, err
	}
}

func ValidateRevokeCARequest(request api.RevokeCAInput) error {
	RevokeCARequestStructLevelValidation := func(sl validator.StructLevel) {
		input := sl.Current().Interface().(api.RevokeCAInput)
		if input.RevocationReason == "" {
			sl.ReportError(input.RevocationReason, "RevocationReason", "RevocationReason", "RevocationReasonNotEmpty", "")
		}
	}
	validate := validator.New()
	validate.RegisterStructValidation(RevokeCARequestStructLevelValidation, api.RevokeCAInput{})
	return validate.Struct(request)
}

func MakeRevokeCAEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.RevokeCAInput)

		err = ValidateRevokeCARequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.RevokeCA(ctx, &input)
		return output, err
	}
}

// func ValidateImportCARequest(request api.ImportCAInput) error {
// 	ImportCARequestStructLevelValidation := func(sl validator.StructLevel) {
// 		_ = sl.Current().Interface().(api.ImportCAInput)
// 	}
// 	validate := validator.New()
// 	validate.RegisterStructValidation(ImportCARequestStructLevelValidation, api.ImportCAInput{})
// 	return validate.Struct(request)
// }

// func MakeImportCAEndpoint(s service.Service) endpoint.Endpoint {
// 	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
// 		req := request.(api.ImportCAInput)

// 		err = ValidateImportCARequest(req)
// 		if err != nil {
// 			valError := errors.ValidationError{
// 				Msg: err.Error(),
// 			}
// 			return nil, &valError
// 		}

// 		ca, err := s.ImportCA(ctx, caType, req.CaName, *crt, privKey, req.CaPayload.EnrollerTTL)
// 		return ca, err
// 	}
// }

func ValidateGetCertificatesRequest(request api.GetCertificatesInput) error {
	GetCertificatesRequestStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetCertificatesInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(GetCertificatesRequestStructLevelValidation, api.GetCertificatesInput{})
	return validate.Struct(request)
}

func MakeGetCertificatesEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetCertificatesInput)

		err = ValidateGetCertificatesRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.GetCertificates(ctx, &input)
		return output, err
	}
}

func ValidateGetCertificateBySerialNumberRequest(request api.GetCertificateBySerialNumberInput) error {
	GetCertificateBySerialNumberRequestStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetCertificateBySerialNumberInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(GetCertificateBySerialNumberRequestStructLevelValidation, api.GetCertificateBySerialNumberInput{})
	return validate.Struct(request)
}

func MakeCertEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetCertificateBySerialNumberInput)

		err = ValidateGetCertificateBySerialNumberRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.GetCertificateBySerialNumber(ctx, &input)
		return output, err
	}
}

func ValidateSignCertificateRequestRequest(request api.SignCertificateRequestInput) error {
	SignCertificateRequestRequestStructLevelValidation := func(sl validator.StructLevel) {
		input := sl.Current().Interface().(api.SignCertificateRequestInput)
		if !input.SignVerbatim && input.CommonName == "" {
			sl.ReportError(input.CommonName, "CommonName", "CommonName", "CommonNameNotEmptyIfNotSignVerbatim", "")
		}
	}
	validate := validator.New()
	validate.RegisterStructValidation(SignCertificateRequestRequestStructLevelValidation, api.SignCertificateRequestInput{})
	return validate.Struct(request)
}

func MakeSignCertEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.SignCertificateRequestInput)

		err = ValidateSignCertificateRequestRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.SignCertificateRequest(ctx, &input)
		return output, err
	}
}

func ValidateRevokeCertificateRequest(request api.RevokeCertificateInput) error {
	RevokeCertificateRequestStructLevelValidation := func(sl validator.StructLevel) {
		input := sl.Current().Interface().(api.RevokeCertificateInput)
		if input.RevocationReason == "" {
			sl.ReportError(input.RevocationReason, "RevocationReason", "RevocationReason", "RevocationReasonNotEmpty", "")
		}
	}
	validate := validator.New()
	validate.RegisterStructValidation(RevokeCertificateRequestStructLevelValidation, api.RevokeCertificateInput{})
	return validate.Struct(request)
}

func MakeRevokeCertEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.RevokeCertificateInput)

		err = ValidateRevokeCertificateRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.RevokeCertificate(ctx, &input)
		return output, err
	}
}

type HealthResponse struct {
	Healthy bool `json:"healthy,omitempty"`
}
