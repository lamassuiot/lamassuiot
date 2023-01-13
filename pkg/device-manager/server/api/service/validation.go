package service

import (
	"context"
	"crypto/rsa"
	"crypto/x509"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/errors"
)

type validationMiddleware struct {
	next Service
}

func NewInputValudationMiddleware() Middleware {
	return func(next Service) Service {
		return &validationMiddleware{
			next: next,
		}
	}
}

func (mw *validationMiddleware) Health(ctx context.Context) (healthy bool) {
	return mw.next.Health(ctx)
}

func (mw *validationMiddleware) GetStats(ctx context.Context, input *api.GetStatsInput) (*api.GetStatsOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.GetStats(ctx, input)
}

func (mw *validationMiddleware) CreateDevice(ctx context.Context, input *api.CreateDeviceInput) (*api.CreateDeviceOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.CreateDevice(ctx, input)
}

func (mw *validationMiddleware) UpdateDeviceMetadata(ctx context.Context, input *api.UpdateDeviceMetadataInput) (*api.UpdateDeviceMetadataOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.UpdateDeviceMetadata(ctx, input)
}

func (mw *validationMiddleware) DecommisionDevice(ctx context.Context, input *api.DecommisionDeviceInput) (*api.DecommisionDeviceOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.DecommisionDevice(ctx, input)
}

func (mw *validationMiddleware) GetDevices(ctx context.Context, input *api.GetDevicesInput) (*api.GetDevicesOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.GetDevices(ctx, input)
}

func (mw *validationMiddleware) GetDeviceById(ctx context.Context, input *api.GetDeviceByIdInput) (*api.GetDeviceByIdOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.GetDeviceById(ctx, input)
}

func (mw *validationMiddleware) AddDeviceSlot(ctx context.Context, input *api.AddDeviceSlotInput) (*api.AddDeviceSlotOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.AddDeviceSlot(ctx, input)
}

func (mw *validationMiddleware) UpdateActiveCertificateStatus(ctx context.Context, input *api.UpdateActiveCertificateStatusInput) (*api.UpdateActiveCertificateStatusOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.UpdateActiveCertificateStatus(ctx, input)
}

func (mw *validationMiddleware) RotateActiveCertificate(ctx context.Context, input *api.RotateActiveCertificateInput) (*api.RotateActiveCertificateOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.RotateActiveCertificate(ctx, input)
}

func (mw *validationMiddleware) RevokeActiveCertificate(ctx context.Context, input *api.RevokeActiveCertificateInput) (*api.RevokeActiveCertificateOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.RevokeActiveCertificate(ctx, input)
}

func (mw *validationMiddleware) GetDeviceLogs(ctx context.Context, input *api.GetDeviceLogsInput) (*api.GetDeviceLogsOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.GetDeviceLogs(ctx, input)
}

func (mw *validationMiddleware) IsDMSAuthorizedToEnroll(ctx context.Context, input *api.IsDMSAuthorizedToEnrollInput) (*api.IsDMSAuthorizedToEnrollOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.IsDMSAuthorizedToEnroll(ctx, input)
}

func (mw *validationMiddleware) ForceReenroll(ctx context.Context, input *api.ForceReenrollInput) (*api.ForceReenrollOtput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.ForceReenroll(ctx, input)
}

func (mw *validationMiddleware) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	return mw.next.CACerts(ctx, aps)
}

func (mw *validationMiddleware) Enroll(ctx context.Context, csr *x509.CertificateRequest, clientCertificate *x509.Certificate, aps string) (*x509.Certificate, error) {
	return mw.next.Enroll(ctx, csr, clientCertificate, aps)
}

func (mw *validationMiddleware) Reenroll(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate) (*x509.Certificate, error) {
	return mw.next.Reenroll(ctx, csr, cert)
}

func (mw *validationMiddleware) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (*x509.Certificate, *rsa.PrivateKey, error) {
	return mw.next.ServerKeyGen(ctx, csr, cert, aps)
}
