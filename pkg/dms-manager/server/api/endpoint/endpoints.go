package endpoint

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	dmsenrrors "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/service"
)

type Endpoints struct {
	HealthEndpoint                 endpoint.Endpoint
	CreateDMSEndpoint              endpoint.Endpoint
	UpdateDMSStatusEndpoint        endpoint.Endpoint
	UpdateDMSAuthorizedCAsEndpoint endpoint.Endpoint
	UpdateDMSEndpoint              endpoint.Endpoint
	GetDMSsEndpoint                endpoint.Endpoint
	GetDMSByNameEndpoint           endpoint.Endpoint
}

func MakeServerEndpoints(s service.Service) Endpoints {
	var healthEndpoint = MakeHealthEndpoint(s)
	var createDMSEndpoint = MakeCreateDMSEndpoint(s)
	var getDMSsEndpoint = MakeGetDMSsEndpoint(s)
	var getDMSByNameEndpoint = MakeGetDMSByNameEndpoint(s)
	var updateDMSStatusEndpoint = MakeUpdateDMSStatusEndpoint(s)
	var updateDMSAuthorizedCAsEndpointEndpoint = MakeUpdateDMSAuthorizedCAsEndpoint(s)
	var updateDMSEndpoint = MakeUpdateDMSEndpoint(s)

	return Endpoints{
		HealthEndpoint:                 healthEndpoint,
		CreateDMSEndpoint:              createDMSEndpoint,
		UpdateDMSStatusEndpoint:        updateDMSStatusEndpoint,
		UpdateDMSAuthorizedCAsEndpoint: updateDMSAuthorizedCAsEndpointEndpoint,
		GetDMSsEndpoint:                getDMSsEndpoint,
		GetDMSByNameEndpoint:           getDMSByNameEndpoint,
		UpdateDMSEndpoint:              updateDMSEndpoint,
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

		if input.Name == "" {
			sl.ReportError(input.Name, "Name", "Name", "NameIsEmpty", "")
		}

		if input.CloudDMS {
			if len(input.IdentityProfile.EnrollmentSettings.BootstrapCAs) == 0 {
				sl.ReportError(input.IdentityProfile.EnrollmentSettings.BootstrapCAs, "BootstrapCAs", "BootstrapCAs", "BootstrapCAsIsEmpty", "")
			}
		} else {
			if input.Name != input.RemoteAccessIdentity.Subject.CommonName {
				sl.ReportError(input.Name, "CommonName", "CommonName", "CommonNameAndNameMissmatch", "")
			}

			if input.RemoteAccessIdentity.KeyMetadata.KeyType == api.RSA {
				if input.RemoteAccessIdentity.KeyMetadata.KeyBits%1024 != 0 || input.RemoteAccessIdentity.KeyMetadata.KeyBits == 0 {
					sl.ReportError(input.RemoteAccessIdentity.KeyMetadata.KeyBits, "KeyBits", "KeyBits", "InvalidRSAKeyBits", "")
				}
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
	UpdateDMSAuthCAsStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.UpdateDMSAuthorizedCAsInput)
	}

	validate := validator.New()
	validate.RegisterStructValidation(UpdateDMSAuthCAsStructLevelValidation, api.UpdateDMSAuthorizedCAsInput{})
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
func ValidateUpdateDMS(request api.UpdateDMSInput) error {
	UpdateDMSStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.UpdateDMSInput)
	}

	validate := validator.New()
	validate.RegisterStructValidation(UpdateDMSStructLevelValidation, api.UpdateDMSInput{})
	return validate.Struct(request)
}

func MakeUpdateDMSEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.UpdateDMSInput)
		err = ValidateUpdateDMS(input)
		if err != nil {
			valError := dmsenrrors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}
		output, err := s.UpdateDMS(ctx, &input)
		return output, err
	}
}

type HealthResponse struct {
	Healthy bool `json:"healthy,omitempty"`
}
