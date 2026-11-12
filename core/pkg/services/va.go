package services

import (
	"context"
	"crypto/x509"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"golang.org/x/crypto/ocsp"
)

type VAService interface {
	GetOCSPResponseGet(ctx context.Context, input GetOCSPResponseInput) (*ocsp.Response, error)
	GetOCSPResponsePost(ctx context.Context, input GetOCSPResponseInput) (*ocsp.Response, error)
	GetCRL(ctx context.Context, input GetCRLResponseInput) (*x509.RevocationList, error)
	GetCRLSettingsList(ctx context.Context, input GetCRLSettingsListInput) (string, error)
	GetCRLSettingsByID(ctx context.Context, input GetCRLSettingsInput) (*models.CRLSettings, error)
	UpdateCRLSettings(ctx context.Context, input UpdateCRLSettingsInput) (*models.CRLSettings, error)
}

type GetOCSPResponseInput struct {
	Certificate    *x509.Certificate
	Issuer         *x509.Certificate
	VerifyResponse bool
}

type GetCRLResponseInput struct {
	// ID is the ID of a CA or the SKI of its key (the CDP of certificates issued before CRL settings moved to the CA ID).
	ID             string
	Issuer         *x509.Certificate
	VerifyResponse bool
}
