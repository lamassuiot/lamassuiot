package validator

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/v2/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/sirupsen/logrus"
)

type CAValidator struct {
	Logger    *logrus.Entry
	Next      services.CAService
	Validator *validator.Validate
}

func createCAValidation(sl validator.StructLevel) {
	ca := sl.Current().Interface().(services.CreateCAInput)
	if !helpers.ValidateExpirationTimeRef(ca.CAExpiration) {
		sl.ReportError(ca.CAExpiration, "ca_expiration", "CAExpiration", "Invalid CA Expiration", "")
	}

	if !helpers.ValidateExpirationTimeRef(ca.IssuanceExpiration) {
		sl.ReportError(ca.IssuanceExpiration, "issuance_expiration", "IssuanceExpiration", "Invalid Issuance Expiration", "")
	}

	expiration := time.Now()
	if ca.CAExpiration.Type == models.Duration {
		expiration = expiration.Add(time.Duration(*ca.CAExpiration.Duration))
	} else {
		expiration = *ca.CAExpiration.Time
	}

	if !helpers.ValidateCAExpiration(ca.IssuanceExpiration, expiration) {
		sl.ReportError(ca.IssuanceExpiration, "issuance_expiration", "IssuanceExpiration", "Issuance Expiration is greater than CA Expiration", "")
	}
}

func importCAValidation(sl validator.StructLevel) {
	ca := sl.Current().Interface().(services.ImportCAInput)
	caCert := ca.CACertificate

	if ca.CAType != models.CertificateTypeExternal {
		if !helpers.ValidateCAExpiration(ca.IssuanceExpiration, caCert.NotAfter) {
			sl.ReportError(ca.IssuanceExpiration, "issuance_expiration", "IssuanceExpiration", "Issuance Expiration is greater than CA Expiration", "")
		}

		if !helpers.ValidateExpirationTimeRef(ca.IssuanceExpiration) {
			sl.ReportError(ca.IssuanceExpiration, "issuance_expiration", "IssuanceExpiration", "Invalid Issuance Expiration", "")
		}

		valid, err := helpers.ValidateCertAndPrivKey((*x509.Certificate)(caCert), ca.CARSAKey, ca.CAECKey)
		if err != nil || !valid {
			sl.ReportError(ca.CARSAKey, "key", "CARSAKey", "Private key and certificate don't match", "")
			sl.ReportError(ca.CAECKey, "key", "CAECKey", "Private key and certificate don't match", "")
		}
	}
}

func NewCAValidator(logger *logrus.Entry) services.CAMiddleware {
	return func(next services.CAService) services.CAService {
		validator := validator.New()

		validator.RegisterStructValidation(importCAValidation, services.ImportCAInput{})
		validator.RegisterStructValidation(createCAValidation, services.CreateCAInput{})

		return &CAValidator{
			Next:      next,
			Validator: validator,
			Logger:    logger,
		}
	}
}

func (mw CAValidator) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	return mw.Next.GetCryptoEngineProvider(ctx)
}

func (mw CAValidator) GetStats(ctx context.Context) (*models.CAStats, error) {
	return mw.Next.GetStats(ctx)
}

func (mw CAValidator) GetStatsByCAID(ctx context.Context, input services.GetStatsByCAIDInput) (map[models.CertificateStatus]int, error) {
	err := mw.Validator.Struct(input)
	if err != nil {
		logInputValidationError(err, mw.Logger)
		return nil, errs.ErrInvalidInput
	}

	return mw.Next.GetStatsByCAID(ctx, input)
}

func (mw CAValidator) CreateCA(ctx context.Context, input services.CreateCAInput) (*models.CACertificate, error) {
	err := mw.Validator.Struct(input)
	if err != nil {
		logInputValidationError(err, mw.Logger)
		return nil, errs.ErrInvalidInput
	}

	return mw.Next.CreateCA(ctx, input)
}

func (mw CAValidator) ImportCA(ctx context.Context, input services.ImportCAInput) (*models.CACertificate, error) {
	err := mw.Validator.Struct(input)
	if err != nil {
		logInputValidationError(err, mw.Logger)
		return nil, errs.ErrInvalidInput
	}

	return mw.Next.ImportCA(ctx, input)
}

func (mw CAValidator) GetCAByID(ctx context.Context, input services.GetCAByIDInput) (*models.CACertificate, error) {
	return mw.Next.GetCAByID(ctx, input)
}

func (mw CAValidator) GetCAs(ctx context.Context, input services.GetCAsInput) (string, error) {
	return mw.Next.GetCAs(ctx, input)
}

func (mw CAValidator) GetCAsByCommonName(ctx context.Context, input services.GetCAsByCommonNameInput) (string, error) {
	return mw.Next.GetCAsByCommonName(ctx, input)
}

func (mw CAValidator) UpdateCAStatus(ctx context.Context, input services.UpdateCAStatusInput) (output *models.CACertificate, err error) {
	return mw.Next.UpdateCAStatus(ctx, input)
}

func (mw CAValidator) UpdateCAMetadata(ctx context.Context, input services.UpdateCAMetadataInput) (output *models.CACertificate, err error) {
	return mw.Next.UpdateCAMetadata(ctx, input)
}

func (mw CAValidator) DeleteCA(ctx context.Context, input services.DeleteCAInput) (err error) {
	return mw.Next.DeleteCA(ctx, input)
}

func (mw CAValidator) SignCertificate(ctx context.Context, input services.SignCertificateInput) (output *models.Certificate, err error) {
	return mw.Next.SignCertificate(ctx, input)
}

func (mw CAValidator) CreateCertificate(ctx context.Context, input services.CreateCertificateInput) (output *models.Certificate, err error) {
	return mw.Next.CreateCertificate(ctx, input)
}

func (mw CAValidator) ImportCertificate(ctx context.Context, input services.ImportCertificateInput) (output *models.Certificate, err error) {
	return mw.Next.ImportCertificate(ctx, input)
}

func (mw CAValidator) SignatureSign(ctx context.Context, input services.SignatureSignInput) (output []byte, err error) {
	return mw.Next.SignatureSign(ctx, input)
}

func (mw CAValidator) SignatureVerify(ctx context.Context, input services.SignatureVerifyInput) (output bool, err error) {
	return mw.Next.SignatureVerify(ctx, input)
}

func (mw CAValidator) GetCertificateBySerialNumber(ctx context.Context, input services.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	return mw.Next.GetCertificateBySerialNumber(ctx, input)
}

func (mw CAValidator) GetCertificates(ctx context.Context, input services.GetCertificatesInput) (string, error) {
	return mw.Next.GetCertificates(ctx, input)
}

func (mw CAValidator) GetCertificatesByCA(ctx context.Context, input services.GetCertificatesByCAInput) (string, error) {
	return mw.Next.GetCertificatesByCA(ctx, input)
}

func (mw CAValidator) GetCertificatesByExpirationDate(ctx context.Context, input services.GetCertificatesByExpirationDateInput) (string, error) {
	return mw.Next.GetCertificatesByExpirationDate(ctx, input)
}

func (mw CAValidator) UpdateCertificateStatus(ctx context.Context, input services.UpdateCertificateStatusInput) (output *models.Certificate, err error) {
	return mw.Next.UpdateCertificateStatus(ctx, input)
}

func (mw CAValidator) GetCertificatesByCaAndStatus(ctx context.Context, input services.GetCertificatesByCaAndStatusInput) (string, error) {
	return mw.Next.GetCertificatesByCaAndStatus(ctx, input)
}

func (mw CAValidator) GetCertificatesByStatus(ctx context.Context, input services.GetCertificatesByStatusInput) (string, error) {
	return mw.Next.GetCertificatesByStatus(ctx, input)
}

func (mw CAValidator) UpdateCertificateMetadata(ctx context.Context, input services.UpdateCertificateMetadataInput) (output *models.Certificate, err error) {
	return mw.Next.UpdateCertificateMetadata(ctx, input)
}
