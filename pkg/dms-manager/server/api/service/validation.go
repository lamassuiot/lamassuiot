package service

import (
	"context"
	"crypto/rsa"
	"crypto/x509"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/errors"
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

func (mw *validationMiddleware) UpdateDevManagerAddr(devManagerAddr string) {
}

func (mw *validationMiddleware) Health(ctx context.Context) (healthy bool) {
	return mw.next.Health(ctx)
}

func (mw *validationMiddleware) CreateDMS(ctx context.Context, input *api.CreateDMSInput) (*api.CreateDMSOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.CreateDMS(ctx, input)
}

func (mw *validationMiddleware) UpdateDMSStatus(ctx context.Context, input *api.UpdateDMSStatusInput) (*api.UpdateDMSStatusOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.UpdateDMSStatus(ctx, input)
}
func (mw *validationMiddleware) UpdateDMS(ctx context.Context, input *api.UpdateDMSInput) (*api.UpdateDMSOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.UpdateDMS(ctx, input)
}

func (mw *validationMiddleware) UpdateDMSAuthorizedCAs(ctx context.Context, input *api.UpdateDMSAuthorizedCAsInput) (*api.UpdateDMSAuthorizedCAsOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.UpdateDMSAuthorizedCAs(ctx, input)
}

func (mw *validationMiddleware) GetDMSs(ctx context.Context, input *api.GetDMSsInput) (*api.GetDMSsOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.GetDMSs(ctx, input)
}

func (mw *validationMiddleware) GetDMSByName(ctx context.Context, input *api.GetDMSByNameInput) (*api.GetDMSByNameOutput, error) {
	validate := validator.New()
	err := validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.GetDMSByName(ctx, input)
}

func (mw *validationMiddleware) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	return mw.next.CACerts(ctx, aps)
}

func (mw *validationMiddleware) Enroll(ctx context.Context, csr *x509.CertificateRequest, clientCertificate *x509.Certificate, aps string) (*x509.Certificate, error) {
	return mw.next.Enroll(ctx, csr, clientCertificate, aps)
}

func (mw *validationMiddleware) Reenroll(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (*x509.Certificate, error) {
	return mw.next.Reenroll(ctx, csr, cert, aps)
}

func (mw *validationMiddleware) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (*x509.Certificate, *rsa.PrivateKey, error) {
	return mw.next.ServerKeyGen(ctx, csr, cert, aps)
}
