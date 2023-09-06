package service

import (
	"context"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/errors"
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

func (mw *validationMiddleware) Health() (healthy bool) {
	return mw.next.Health()
}

func (s *validationMiddleware) SetService(service Service) {}

func (mw *validationMiddleware) GetEngineProviderInfo() (output api.EngineProviderInfo) {
	return mw.next.GetEngineProviderInfo()
}

func (mw *validationMiddleware) Stats(ctx context.Context, input *api.GetStatsInput) (output *api.GetStatsOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.Stats(ctx, input)
}

func (mw *validationMiddleware) CreateCA(ctx context.Context, input *api.CreateCAInput) (output *api.CreateCAOutput, err error) {
	validatorFunc := func(sl validator.StructLevel) {
		input := sl.Current().Interface().(api.CreateCAInput)

		if input.KeyMetadata.KeyType == api.RSA {
			if input.KeyMetadata.KeyBits%1024 != 0 || input.KeyMetadata.KeyBits == 0 {
				sl.ReportError(input.KeyMetadata.KeyBits, "KeyBits", "KeyBits", "InvalidRSAKeyBits", "")
			}
		}
		if input.IssuanceExpirationType == api.ExpirationTypeDate {
			if input.CAExpiration.Before(*input.IssuanceExpirationDate) {
				sl.ReportError(input.IssuanceExpirationDate, "IssuanceExpiration", "IssuanceExpiration", "IssuanceExpirationGreaterThanCAExpiration", "")
			}
		} else {
			expiration := time.Now().Add(*input.IssuanceExpirationDuration * time.Second)
			if input.CAExpiration.Before(expiration) {
				sl.ReportError(input.IssuanceExpirationDuration, "IssuanceExpiration", "IssuanceExpiration", "IssuanceExpirationGreaterThanCAExpiration", "")
			}
		}

	}
	validate := validator.New()
	validate.RegisterStructValidation(validatorFunc, api.CreateCAInput{})
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}

	return mw.next.CreateCA(ctx, input)
}

func (mw *validationMiddleware) ImportCA(ctx context.Context, input *api.ImportCAInput) (output *api.ImportCAOutput, err error) {
	validatorFunc := func(sl validator.StructLevel) {
		input := sl.Current().Interface().(api.ImportCAInput)
		if input.WithPrivateKey {
			if input.IssuanceExpirationType == api.ExpirationTypeDate {
				if input.Certificate.NotAfter.Before(*input.IssuanceExpirationDate) {
					sl.ReportError(input.IssuanceExpirationDate, "IssuanceExpiration", "IssuanceExpiration", "IssuanceExpirationGreaterThanCAExpiration", "")
				}
			} else {
				expiration := time.Now().Add(*input.IssuanceExpirationDuration * time.Second)
				if input.Certificate.NotAfter.Before(expiration) {
					sl.ReportError(input.IssuanceExpirationDuration, "IssuanceExpiration", "IssuanceExpiration", "IssuanceExpirationGreaterThanCAExpiration", "")
				}
			}
		}

	}
	validate := validator.New()
	validate.RegisterStructValidation(validatorFunc, api.ImportCAInput{})
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.ImportCA(ctx, input)
}

func (mw *validationMiddleware) GetCAs(ctx context.Context, input *api.GetCAsInput) (output *api.GetCAsOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.GetCAs(ctx, input)
}

func (mw *validationMiddleware) GetCAByName(ctx context.Context, input *api.GetCAByNameInput) (output *api.GetCAByNameOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.GetCAByName(ctx, input)
}

func (mw *validationMiddleware) UpdateCAStatus(ctx context.Context, input *api.UpdateCAStatusInput) (output *api.UpdateCAStatusOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.UpdateCAStatus(ctx, input)
}

func (mw *validationMiddleware) RevokeCA(ctx context.Context, input *api.RevokeCAInput) (output *api.RevokeCAOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.RevokeCA(ctx, input)
}

func (mw *validationMiddleware) IterateCAsWithPredicate(ctx context.Context, input *api.IterateCAsWithPredicateInput) (output *api.IterateCAsWithPredicateOutput, err error) {
	return mw.next.IterateCAsWithPredicate(ctx, input)
}

func (mw *validationMiddleware) SignCertificateRequest(ctx context.Context, input *api.SignCertificateRequestInput) (output *api.SignCertificateRequestOutput, err error) {
	validatorFunc := func(sl validator.StructLevel) {
		input := sl.Current().Interface().(api.SignCertificateRequestInput)
		if !input.SignVerbatim && input.CommonName == "" {
			sl.ReportError(input.CommonName, "CommonName", "CommonName", "InvalidSignVerbatimCommonName", "")
		}
	}
	validate := validator.New()
	validate.RegisterStructValidation(validatorFunc, api.SignCertificateRequestInput{})
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.SignCertificateRequest(ctx, input)
}

func (mw *validationMiddleware) RevokeCertificate(ctx context.Context, input *api.RevokeCertificateInput) (output *api.RevokeCertificateOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.RevokeCertificate(ctx, input)
}

func (mw *validationMiddleware) GetCertificateBySerialNumber(ctx context.Context, input *api.GetCertificateBySerialNumberInput) (output *api.GetCertificateBySerialNumberOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.GetCertificateBySerialNumber(ctx, input)
}

func (mw *validationMiddleware) GetCertificates(ctx context.Context, input *api.GetCertificatesInput) (output *api.GetCertificatesOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.GetCertificates(ctx, input)
}

func (mw *validationMiddleware) UpdateCertificateStatus(ctx context.Context, input *api.UpdateCertificateStatusInput) (output *api.UpdateCertificateStatusOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.UpdateCertificateStatus(ctx, input)
}

func (mw *validationMiddleware) IterateCertificatesWithPredicate(ctx context.Context, input *api.IterateCertificatesWithPredicateInput) (output *api.IterateCertificatesWithPredicateOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.IterateCertificatesWithPredicate(ctx, input)
}

func (mw *validationMiddleware) GetCertificatesAboutToExpire(ctx context.Context, input *api.GetCertificatesAboutToExpireInput) (output *api.GetCertificatesAboutToExpireOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.GetCertificatesAboutToExpire(ctx, input)
}

func (mw *validationMiddleware) GetExpiredAndOutOfSyncCertificates(ctx context.Context, input *api.GetExpiredAndOutOfSyncCertificatesInput) (output *api.GetExpiredAndOutOfSyncCertificatesOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.GetExpiredAndOutOfSyncCertificates(ctx, input)
}

func (mw *validationMiddleware) ScanAboutToExpireCertificates(ctx context.Context, input *api.ScanAboutToExpireCertificatesInput) (output *api.ScanAboutToExpireCertificatesOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.ScanAboutToExpireCertificates(ctx, input)
}

func (mw *validationMiddleware) ScanExpiredAndOutOfSyncCertificates(ctx context.Context, input *api.ScanExpiredAndOutOfSyncCertificatesInput) (output *api.ScanExpiredAndOutOfSyncCertificatesOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.ScanExpiredAndOutOfSyncCertificates(ctx, input)
}

func (mw *validationMiddleware) Verify(ctx context.Context, input *api.VerifyInput) (output *api.VerifyOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.Verify(ctx, input)
}

func (mw *validationMiddleware) Sign(ctx context.Context, input *api.SignInput) (output *api.SignOutput, err error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.Sign(ctx, input)
}
