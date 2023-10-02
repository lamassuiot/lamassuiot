package endpoint

import (
	"context"
	"encoding/json"
	"strings"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
)

type Endpoints struct {
	HealthEndpoint                  endpoint.Endpoint
	GetStatsEndpoint                endpoint.Endpoint
	CreateDeviceEndpoint            endpoint.Endpoint
	UpdateDeviceMetadataEndpoint    endpoint.Endpoint
	DecommisionDeviceEndpoint       endpoint.Endpoint
	GetDevicesEndpoint              endpoint.Endpoint
	GetDevicesByDmsEndpoint         endpoint.Endpoint
	GetDeviceByIdEndpoint           endpoint.Endpoint
	RevokeActiveCertificateEndpoint endpoint.Endpoint
	ForceReenrollEndpoint           endpoint.Endpoint
	ImportDeviceCertEndpoint        endpoint.Endpoint
	GetDeviceLogsEndpoint           endpoint.Endpoint
	HandleCACloudEvent              endpoint.Endpoint
}

func MakeServerEndpoints(s service.Service) Endpoints {
	var healthEndpoint = MakeHealthEndpoint(s)
	var getStatsEndpoint = MakeGetStatsEndpoint(s)
	var createDeviceEndpoint = MakeCreateDeviceEndpoint(s)
	var updateDeviceMetadataEndpoint = MakeUpdateDeviceMetadataEndpoint(s)
	var decommisionDeviceEndpoint = MakeDecommisionDeviceEndpoint(s)
	var getDevicesEndpoint = MakeGetDevicesEndpoint(s)
	var getDevicesByDmsEndpoint = MakeGetDevicesByDmsEndpoint(s)
	var getDeviceByIdEndpoint = MakeGetDeviceByIdEndpoint(s)
	var revokeActiveCertificateEndpoint = MakeRevokeActiveCertificateEndpoint(s)
	var getDeviceLogsEndpoint = MakeGetDeviceLogsEndpoint(s)
	var importDeviceCertEndpoint = MakeImportDeviceCertEndpoint(s)
	var handleCACloudEvent = MakeHandleCACloudEvent(s)
	var forceReenrollEndpoint = MakeForceReenrollEnpoint(s)

	return Endpoints{
		HealthEndpoint:                  healthEndpoint,
		GetStatsEndpoint:                getStatsEndpoint,
		CreateDeviceEndpoint:            createDeviceEndpoint,
		UpdateDeviceMetadataEndpoint:    updateDeviceMetadataEndpoint,
		DecommisionDeviceEndpoint:       decommisionDeviceEndpoint,
		GetDevicesEndpoint:              getDevicesEndpoint,
		GetDevicesByDmsEndpoint:         getDevicesByDmsEndpoint,
		GetDeviceByIdEndpoint:           getDeviceByIdEndpoint,
		RevokeActiveCertificateEndpoint: revokeActiveCertificateEndpoint,
		GetDeviceLogsEndpoint:           getDeviceLogsEndpoint,
		HandleCACloudEvent:              handleCACloudEvent,
		ForceReenrollEndpoint:           forceReenrollEndpoint,
		ImportDeviceCertEndpoint:        importDeviceCertEndpoint,
	}
}

func MakeHealthEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		output := s.Health(ctx)
		return HealthResponse{Healthy: output}, nil
	}
}

func ValidateGetStatsRequest(request api.GetStatsInput) error {
	GetStatsInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetStatsInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(GetStatsInputStructLevelValidation, api.GetStatsInput{})
	return validate.Struct(request)
}
func MakeGetStatsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetStatsInput)

		err = ValidateGetStatsRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.GetStats(ctx, &input)
		return output, err
	}
}

func ValidateCreateDeviceRequest(request api.CreateDeviceInput) error {
	CreateDeviceInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.CreateDeviceInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(CreateDeviceInputStructLevelValidation, api.CreateDeviceInput{})
	return validate.Struct(request)
}
func MakeCreateDeviceEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.CreateDeviceInput)

		err = ValidateCreateDeviceRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.CreateDevice(ctx, &input)
		return output, err
	}
}

func ValidateUpdateDeviceMetadataRequest(request api.UpdateDeviceMetadataInput) error {
	UpdateDeviceMetadataInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.UpdateDeviceMetadataInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(UpdateDeviceMetadataInputStructLevelValidation, api.UpdateDeviceMetadataInput{})
	return validate.Struct(request)
}
func MakeUpdateDeviceMetadataEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.UpdateDeviceMetadataInput)

		err = ValidateUpdateDeviceMetadataRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.UpdateDeviceMetadata(ctx, &input)
		return output, err
	}
}

func ValidateDecommisionDeviceRequest(request api.DecommisionDeviceInput) error {
	DecommisionDeviceInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.DecommisionDeviceInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(DecommisionDeviceInputStructLevelValidation, api.DecommisionDeviceInput{})
	return validate.Struct(request)
}
func MakeDecommisionDeviceEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.DecommisionDeviceInput)

		err = ValidateDecommisionDeviceRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.DecommisionDevice(ctx, &input)
		return output, err
	}
}

func ValidateGetDevicesRequest(request api.GetDevicesInput) error {
	GetDevicesInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetDevicesInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(GetDevicesInputStructLevelValidation, api.GetDevicesInput{})
	return validate.Struct(request)
}
func MakeGetDevicesEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetDevicesInput)

		err = ValidateGetDevicesRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.GetDevices(ctx, &input)
		return output, err
	}
}

func ValidateGetDevicesByDmsRequest(request api.GetDevicesByDMSInput) error {
	GetDevicesByDmsInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetDevicesByDMSInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(GetDevicesByDmsInputStructLevelValidation, api.GetDevicesByDMSInput{})
	return validate.Struct(request)
}
func MakeGetDevicesByDmsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetDevicesByDMSInput)

		err = ValidateGetDevicesByDmsRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.GetDevicesByDMS(ctx, &input)
		return output, err
	}
}

func ValidateGetDeviceByIdRequest(request api.GetDeviceByIdInput) error {
	GetDeviceByIdInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetDeviceByIdInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(GetDeviceByIdInputStructLevelValidation, api.GetDeviceByIdInput{})
	return validate.Struct(request)
}
func MakeGetDeviceByIdEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetDeviceByIdInput)

		err = ValidateGetDeviceByIdRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.GetDeviceById(ctx, &input)
		return output, err
	}
}

func ValidateRevokeActiveCertificateRequest(request api.RevokeActiveCertificateInput) error {
	RevokeActiveCertificateInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.RevokeActiveCertificateInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(RevokeActiveCertificateInputStructLevelValidation, api.RevokeActiveCertificateInput{})
	return validate.Struct(request)
}
func MakeRevokeActiveCertificateEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.RevokeActiveCertificateInput)

		err = ValidateRevokeActiveCertificateRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.RevokeActiveCertificate(ctx, &input)
		return output, err
	}
}

func ValidateGetDeviceLogsRequest(request api.GetDeviceLogsInput) error {
	GetDeviceLogsInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetDeviceLogsInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(GetDeviceLogsInputStructLevelValidation, api.GetDeviceLogsInput{})
	return validate.Struct(request)
}
func MakeGetDeviceLogsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.GetDeviceLogsInput)

		err = ValidateGetDeviceLogsRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.GetDeviceLogs(ctx, &input)
		return output, err
	}
}

func ValidateImportDeviceCertRequest(request api.ImportDeviceCertInput) error {
	GetDeviceLogsInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.GetDeviceLogsInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(GetDeviceLogsInputStructLevelValidation, api.GetDeviceLogsInput{})
	return validate.Struct(request)
}
func MakeImportDeviceCertEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.ImportDeviceCertInput)

		err = ValidateImportDeviceCertRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		output, err := s.ImportDeviceCert(ctx, &input)
		return output, err
	}
}
func MakeHandleCACloudEvent(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		event := request.(cloudevents.Event)
		switch event.Type() {
		case string(models.EventUpdateCertificateStatus):
			var data models.Certificate
			json.Unmarshal(event.Data(), &data)
			cetificate := data

			deviceID := ""
			slotID := "default"
			if strings.Contains(cetificate.Certificate.Subject.CommonName, ":") {
				identifier := strings.Split(cetificate.Certificate.Subject.CommonName, ":")
				slotID = identifier[0]
				deviceID = identifier[1]
			} else {
				deviceID = cetificate.Certificate.Subject.CommonName
			}
			if cetificate.Status == models.StatusExpired {

				_, err = s.ForceReenroll(ctx, &api.ForceReenrollInput{
					DeviceID:      deviceID,
					SlotID:        slotID,
					ForceReenroll: true,
				})
			} else {
				_, err = s.UpdateActiveCertificateStatus(ctx, &api.UpdateActiveCertificateStatusInput{
					DeviceID:         deviceID,
					SlotID:           slotID,
					Status:           cetificate.Status,
					RevocationReason: "",
				})
			}

			return nil, err

		// case "io.lamassuiot.certificate.revoke":
		// 	var data models.RevokeCertificateOutputSerialized
		// 	json.Unmarshal(event.Data(), &data)
		// 	cetificate := data.CertificateSerialized.Deserialize()

		// 	deviceID := ""
		// 	slotID := "default"
		// 	if strings.Contains(cetificate.Certificate.Subject.CommonName, ":") {
		// 		identifier := strings.Split(cetificate.Certificate.Subject.CommonName, ":")
		// 		slotID = identifier[0]
		// 		deviceID = identifier[1]
		// 	} else {
		// 		deviceID = cetificate.Certificate.Subject.CommonName
		// 	}

		// 	_, err = s.UpdateActiveCertificateStatus(ctx, &api.UpdateActiveCertificateStatusInput{
		// 		DeviceID:         deviceID,
		// 		SlotID:           slotID,
		// 		Status:           cetificate.Status,
		// 		RevocationReason: cetificate.RevocationReason,
		// 		CertSerialNumber: cetificate.SerialNumber,
		// 	})
		// 	return nil, err

		default:
			return nil, nil
		}
	}
}

func ValidateForceReenrollRequest(request api.ForceReenrollInput) error {
	ForceReenrollInputStructLevelValidation := func(sl validator.StructLevel) {
		_ = sl.Current().Interface().(api.ForceReenrollInput)
	}
	validate := validator.New()
	validate.RegisterStructValidation(ForceReenrollInputStructLevelValidation, api.ForceReenrollInput{})
	return validate.Struct(request)
}
func MakeForceReenrollEnpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		input := request.(api.ForceReenrollInput)

		err = ValidateForceReenrollRequest(input)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		out, err := s.ForceReenroll(ctx, &input)
		return out, err
	}
}

type HealthResponse struct {
	Healthy bool  `json:"healthy,omitempty"`
	Err     error `json:"err,omitempty"`
}
