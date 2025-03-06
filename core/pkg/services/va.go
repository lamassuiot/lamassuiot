package services

import (
	"context"
	"crypto/x509"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"golang.org/x/crypto/ocsp"
)

type VAService interface {
	GetOCSPResponseGet(ctx context.Context, input GetOCSPResponseInput) (*ocsp.Response, error)
	GetOCSPResponsePost(ctx context.Context, input GetOCSPResponseInput) (*ocsp.Response, error)
	GetCRL(ctx context.Context, inpùt GetCRLResponseInput) (*x509.RevocationList, error)
	GetVARoles(ctx context.Context, input GetVARolesInput) (string, error)
	GetVARoleByID(ctx context.Context, input GetVARoleInput) (*models.VARole, error)
	UpdateVARole(ctx context.Context, input UpdateVARoleInput) (*models.VARole, error)
}

type GetOCSPResponseInput struct {
	Certificate    *x509.Certificate
	Issuer         *x509.Certificate
	VerifyResponse bool
}

type GetCRLResponseInput struct {
	CASubjectKeyID string
	Issuer         *x509.Certificate
	VerifyResponse bool
}
