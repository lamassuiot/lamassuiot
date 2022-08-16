package repository

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
)

type Certificates interface {
	SelectCertificatesByCA(ctx context.Context, CAType api.CAType, CAName string, queryParameters common.QueryParameters) (int, []api.Certificate, error)
	SelectCertificateBySerialNumber(ctx context.Context, CAType api.CAType, CAName string, serialNumber string) (api.Certificate, error)
	UpdateCertificateStatus(ctx context.Context, CAType api.CAType, CAName string, serialNumber string, status api.CertificateStatus, revocationReason string) error
	InsertCertificate(ctx context.Context, CAType api.CAType, CAName string, cert *x509.Certificate) error

	InsertCA(ctx context.Context, CAType api.CAType, certificate *x509.Certificate, issuanceDuration time.Duration) error
	SelectCAByName(ctx context.Context, CAType api.CAType, CAName string) (api.CACertificate, error)
	SelectCAs(ctx context.Context, CAType api.CAType, queryParameters common.QueryParameters) (int, []api.CACertificate, error)
	UpdateCAStatus(ctx context.Context, CAType api.CAType, CAName string, status api.CertificateStatus, revocationReason string) error
}
