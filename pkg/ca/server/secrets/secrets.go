package secrets

import (
	"context"
	"crypto/x509"

	"github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/models/ca"
)

type CAImport struct {
	PEMBundle string `json:"pem_bundle"`
	TTL       int    `json:"ttl"`
}

const (
	StatusValid   = "V"
	StatusRevoked = "R"
	StatusExpired = "E"
)

// CAs represents a list of CAs with minimum information
// swagger:model

type Secrets interface {
	GetSecretProviderName(ctx context.Context) string

	GetCAs(ctx context.Context, caType dto.CAType) ([]dto.Cert, error)
	GetCA(ctx context.Context, caType dto.CAType, caName string) (dto.Cert, error)
	CreateCA(ctx context.Context, caType dto.CAType, caName string, privateKeyMetadata dto.PrivateKeyMetadata, subject dto.Subject, caTTL int, enrollerTTL int) (dto.Cert, error)
	ImportCA(ctx context.Context, caType dto.CAType, caName string, certificate x509.Certificate, privateKey dto.PrivateKey, enrollerTTL int) (dto.Cert, error)
	DeleteCA(ctx context.Context, caType dto.CAType, caName string) error

	GetIssuedCerts(ctx context.Context, caType dto.CAType, caName string, serialnumbers []ca.IssuedCerts) ([]dto.Cert, error)
	GetCert(ctx context.Context, caType dto.CAType, caName string, serialNumber string) (dto.Cert, error)
	DeleteCert(ctx context.Context, caType dto.CAType, caName string, serialNumber string) error

	SignCertificate(ctx context.Context, caType dto.CAType, CAcaName string, csr *x509.CertificateRequest, signVerbatim bool) (dto.SignResponse, error)
}
