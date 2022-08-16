package endpoint

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	dmsenrrors "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/service"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type Endpoints struct {
	HealthEndpoint                 endpoint.Endpoint
	CreateDMSEndpoint              endpoint.Endpoint
	CreateDMSWithCSREndpoint       endpoint.Endpoint
	UpdateDMSStatusEndpoint        endpoint.Endpoint
	UpdateDMSAuthorizedCAsEndpoint endpoint.Endpoint
	GetDMSsEndpoint                endpoint.Endpoint
	GetDMSByNameEndpoint           endpoint.Endpoint
}

func MakeServerEndpoints(s service.Service, otTracer stdopentracing.Tracer) Endpoints {
	var healthEndpoint endpoint.Endpoint
	{
		healthEndpoint = MakeHealthEndpoint(s)
		healthEndpoint = opentracing.TraceServer(otTracer, "Health")(healthEndpoint)
	}
	var createDMSEndpoint endpoint.Endpoint
	{
		createDMSEndpoint = MakeCreateDMSEndpoint(s)
		createDMSEndpoint = opentracing.TraceServer(otTracer, "Create DMS")(createDMSEndpoint)
	}
	var createDMSWithCertificateRequest endpoint.Endpoint
	{
		createDMSWithCertificateRequest = MakeCreateDMSWithCertificateRequestEndpoint(s)
		createDMSWithCertificateRequest = opentracing.TraceServer(otTracer, "Create DMS with Certificate Request")(createDMSWithCertificateRequest)
	}

	var getDMSsEndpoint endpoint.Endpoint
	{
		getDMSsEndpoint = MakeGetDMSsEndpoint(s)
		getDMSsEndpoint = opentracing.TraceServer(otTracer, "GetDMSs")(getDMSsEndpoint)
	}
	var getDMSByNameEndpoint endpoint.Endpoint
	{
		getDMSByNameEndpoint = MakeGetDMSByNameEndpoint(s)
		getDMSByNameEndpoint = opentracing.TraceServer(otTracer, "Get DMS by name")(getDMSByNameEndpoint)
	}
	var updateDMSStatusEndpoint endpoint.Endpoint
	{
		updateDMSStatusEndpoint = MakeUpdateDMSStatusEndpoint(s)
		updateDMSStatusEndpoint = opentracing.TraceServer(otTracer, "Update DMS status")(updateDMSStatusEndpoint)
	}
	var updateDMSAuthorizedCAsEndpointEndpoint endpoint.Endpoint
	{
		updateDMSAuthorizedCAsEndpointEndpoint = MakeUpdateDMSAuthorizedCAsEndpoint(s)
		updateDMSAuthorizedCAsEndpointEndpoint = opentracing.TraceServer(otTracer, "Update DMS authorized CAs")(updateDMSAuthorizedCAsEndpointEndpoint)
	}

	return Endpoints{
		HealthEndpoint:                 healthEndpoint,
		CreateDMSEndpoint:              createDMSEndpoint,
		CreateDMSWithCSREndpoint:       createDMSWithCertificateRequest,
		UpdateDMSStatusEndpoint:        updateDMSStatusEndpoint,
		UpdateDMSAuthorizedCAsEndpoint: updateDMSAuthorizedCAsEndpointEndpoint,
		GetDMSsEndpoint:                getDMSsEndpoint,
		GetDMSByNameEndpoint:           getDMSByNameEndpoint,
	}
}

func MakeHealthEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		healthy := s.Health(ctx)
		return HealthResponse{Healthy: healthy}, nil
	}
}

func ValidateCreateDMS(request api.CreateDMSInput) error {
	CreateDMSStructLevelValidation := func(sl validator.StructLevel) {
		input := sl.Current().Interface().(api.CreateDMSInput)
		if input.Subject.CommonName == "" {
			sl.ReportError(input.Subject.CommonName, "CommonName", "CommonName", "CommonNameIsEmpty", "")
		}

		if input.KeyMetadata.KeyType == api.RSA {
			if input.KeyMetadata.KeyBits%1024 != 0 || input.KeyMetadata.KeyBits == 0 {
				sl.ReportError(input.KeyMetadata.KeyBits, "KeyBits", "KeyBits", "InvalidRSAKeyBits", "")
			}
		}
	}

	validate := validator.New()
	validate.RegisterStructValidation(CreateDMSStructLevelValidation, api.CreateDMSInput{})
	return validate.Struct(request)
}

func MakeCreateDMSEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.CreateDMSInput)
		err = ValidateCreateDMS(input)
		if err != nil {
			valError := dmsenrrors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}
		output, err := s.CreateDMS(ctx, &input)
		return output, err
	}
}

func ValidateCreateDMSWithCertificateRequest(request api.CreateDMSWithCertificateRequestInput) error {
	CreateDMSWithCertificateRequestStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.CreateDMSWithCertificateRequestInput)
	}

	validate := validator.New()
	validate.RegisterStructValidation(CreateDMSWithCertificateRequestStructLevelValidation, api.CreateDMSWithCertificateRequestInput{})
	return validate.Struct(request)
}

func MakeCreateDMSWithCertificateRequestEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.CreateDMSWithCertificateRequestInput)
		err = ValidateCreateDMSWithCertificateRequest(input)
		if err != nil {
			valError := dmsenrrors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}
		output, err := s.CreateDMSWithCertificateRequest(ctx, &input)
		return output, err
	}
}

func ValidateGetDMSs(request api.GetDMSsInput) error {
	GetDMSsStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetDMSsInput)
	}

	validate := validator.New()
	validate.RegisterStructValidation(GetDMSsStructLevelValidation, api.GetDMSsInput{})
	return validate.Struct(request)
}

func MakeGetDMSsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetDMSsInput)
		err = ValidateGetDMSs(input)
		if err != nil {
			valError := dmsenrrors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}
		output, err := s.GetDMSs(ctx, &input)
		return output, err
	}
}

func ValidateGetDMSByName(request api.GetDMSByNameInput) error {
	GetDMSByNameStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetDMSByNameInput)
	}

	validate := validator.New()
	validate.RegisterStructValidation(GetDMSByNameStructLevelValidation, api.GetDMSByNameInput{})
	return validate.Struct(request)
}

func MakeGetDMSByNameEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetDMSByNameInput)
		err = ValidateGetDMSByName(input)
		if err != nil {
			valError := dmsenrrors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}
		output, err := s.GetDMSByName(ctx, &input)
		return output, err
	}
}

func ValidateUpdateDMSStatus(request api.UpdateDMSStatusInput) error {
	UpdateDMSStatusStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.UpdateDMSStatusInput)
	}

	validate := validator.New()
	validate.RegisterStructValidation(UpdateDMSStatusStructLevelValidation, api.UpdateDMSStatusInput{})
	return validate.Struct(request)
}

func MakeUpdateDMSStatusEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.UpdateDMSStatusInput)
		err = ValidateUpdateDMSStatus(input)
		if err != nil {
			valError := dmsenrrors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}
		output, err := s.UpdateDMSStatus(ctx, &input)
		return output, err
	}
}

func ValidateUpdateDMSAuthorizedCAs(request api.UpdateDMSAuthorizedCAsInput) error {
	UpdateDMSAuthorizedCAsStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.UpdateDMSAuthorizedCAsInput)
	}

	validate := validator.New()
	validate.RegisterStructValidation(UpdateDMSAuthorizedCAsStructLevelValidation, api.UpdateDMSAuthorizedCAsInput{})
	return validate.Struct(request)
}

func MakeUpdateDMSAuthorizedCAsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.UpdateDMSAuthorizedCAsInput)
		err = ValidateUpdateDMSAuthorizedCAs(input)
		if err != nil {
			valError := dmsenrrors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}
		output, err := s.UpdateDMSAuthorizedCAs(ctx, &input)
		return output, err
	}
}

type HealthResponse struct {
	Healthy bool `json:"healthy,omitempty"`
}
