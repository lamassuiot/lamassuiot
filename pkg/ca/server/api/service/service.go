package service

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/models/ca/store"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/secrets"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
)

type Service interface {
	GetSecretProviderName(ctx context.Context) string
	Health(ctx context.Context) bool
	Stats(ctx context.Context) dto.Stats
	GetCAs(ctx context.Context, caType dto.CAType, queryparameters filters.QueryParameters) ([]dto.Cert, int, error)
	CreateCA(ctx context.Context, caType dto.CAType, caName string, privateKeyMetadata dto.PrivateKeyMetadata, subject dto.Subject, caTTL int, enrollerTTL int) (dto.Cert, error)
	ImportCA(ctx context.Context, caType dto.CAType, caName string, certificate x509.Certificate, privateKey dto.PrivateKey, enrollerTTL int) (dto.Cert, error)
	DeleteCA(ctx context.Context, caType dto.CAType, caName string) error
	GetIssuedCerts(ctx context.Context, caType dto.CAType, caName string, queryParameters filters.QueryParameters) ([]dto.Cert, int, error)
	GetCert(ctx context.Context, caType dto.CAType, caName string, serialNumber string) (dto.Cert, error)
	DeleteCert(ctx context.Context, caType dto.CAType, caName string, serialNumber string) error
	SignCertificate(ctx context.Context, caType dto.CAType, signingCaName string, csr x509.CertificateRequest, signVerbatim bool, cn string) (dto.SignResponse, error)
}

type caService struct {
	mtx     sync.RWMutex
	logger  log.Logger
	secrets secrets.Secrets
	casDb   store.DB
}

func NewCAService(logger log.Logger, secrets secrets.Secrets, casDb store.DB) Service {

	return &caService{
		secrets: secrets,
		logger:  logger,
		casDb:   casDb,
	}
}

func (s *caService) GetSecretProviderName(ctx context.Context) string {
	return s.secrets.GetSecretProviderName(ctx)
}

func (s *caService) Health(ctx context.Context) bool {
	return true
}

func (s *caService) Stats(ctx context.Context) dto.Stats {
	stats := dto.Stats{
		IssuedCerts: 0,
		CAs:         0,
		ScanDate:    time.Now(),
	}
	var cas []dto.Cert
	limit := 50
	i := 0
	for {
		certs, _, err := s.GetCAs(ctx, dto.Pki, filters.QueryParameters{Pagination: filters.PaginationOptions{Limit: limit, Offset: i * limit}})
		if err != nil {
			return stats
		}
		if len(certs) == 0 {
			break
		}
		cas = append(cas, certs...)
		i++
	}
	for _, ca := range cas {
		_, issuedCerts, err := s.GetIssuedCerts(ctx, dto.Pki, ca.Name, filters.QueryParameters{Pagination: filters.PaginationOptions{Limit: 10, Offset: 0}})
		if err == nil {
			stats.CAs = stats.CAs + 1
			stats.IssuedCerts = stats.IssuedCerts + issuedCerts
		}
	}

	return stats
}

func (s *caService) GetCAs(ctx context.Context, caType dto.CAType, queryparameters filters.QueryParameters) ([]dto.Cert, int, error) {
	if caType == dto.Pki {
		casDB, totalcas, err := s.casDb.SelectCas(ctx, caType.String(), queryparameters)
		if err != nil {
			return []dto.Cert{}, 0, err
		}
		var CAs []dto.Cert
		for _, v := range casDB {
			ca, _ := s.secrets.GetCA(ctx, caType, v.CaName)
			CAs = append(CAs, ca)
		}
		return CAs, totalcas, nil
	} else {
		CAs, err := s.secrets.GetCAs(ctx, caType)
		if err != nil {
			return []dto.Cert{}, 0, err
		}
		return CAs, len(CAs), nil
	}
}

func (s *caService) CreateCA(ctx context.Context, caType dto.CAType, caName string, privateKeyMetadata dto.PrivateKeyMetadata, subject dto.Subject, caTTL int, enrollerTTL int) (dto.Cert, error) {
	if privateKeyMetadata.KeyType == "RSA" {
		privateKeyMetadata.KeyType = "rsa"
	} else if privateKeyMetadata.KeyType == "EC" {
		privateKeyMetadata.KeyType = "ec"
	}

	createdCa, err := s.secrets.CreateCA(ctx, caType, caName, privateKeyMetadata, subject, caTTL, enrollerTTL)
	if err != nil {
		return dto.Cert{}, err
	}
	s.casDb.InsertCa(ctx, caName, caType.String())
	return createdCa, err
}
func (s *caService) ImportCA(ctx context.Context, caType dto.CAType, caName string, certificate x509.Certificate, privateKey dto.PrivateKey, enrollerTTL int) (dto.Cert, error) {
	ca, err := s.secrets.ImportCA(ctx, caType, caName, certificate, privateKey, enrollerTTL)
	if err != nil {
		return dto.Cert{}, err
	}
	s.casDb.InsertCa(ctx, caName, caType.String())
	return ca, nil
}

func (s *caService) DeleteCA(ctx context.Context, caType dto.CAType, CA string) error {
	err := s.secrets.DeleteCA(ctx, caType, CA)
	if err != nil {
		return err
	}
	s.casDb.DeleteCa(ctx, CA)
	return nil
}

func (s *caService) GetIssuedCerts(ctx context.Context, caType dto.CAType, caName string, queryParameters filters.QueryParameters) ([]dto.Cert, int, error) {
	serialnumbers, length, err := s.casDb.SelectCertsByCA(ctx, caName, queryParameters)
	if err != nil {
		return []dto.Cert{}, 0, err
	}
	certs, err := s.secrets.GetIssuedCerts(ctx, caType, caName, serialnumbers)
	if err != nil {
		return []dto.Cert{}, 0, err
	}
	return certs, length, nil
}
func (s *caService) GetCert(ctx context.Context, caType dto.CAType, caName string, serialNumber string) (dto.Cert, error) {
	certs, err := s.secrets.GetCert(ctx, caType, caName, serialNumber)
	if err != nil {
		return dto.Cert{}, err
	}
	return certs, nil
}

func (s *caService) DeleteCert(ctx context.Context, caType dto.CAType, caName string, serialNumber string) error {
	err := s.secrets.DeleteCert(ctx, caType, caName, serialNumber)
	if err != nil {
		return err
	}
	return nil
}

func (s *caService) SignCertificate(ctx context.Context, caType dto.CAType, caName string, csr x509.CertificateRequest, signVerbatim bool, cn string) (dto.SignResponse, error) {
	certs, err := s.secrets.SignCertificate(ctx, caType, caName, &csr, signVerbatim, cn)
	if err != nil {
		return dto.SignResponse{}, err
	}
	data, _ := base64.StdEncoding.DecodeString(certs.Crt)
	block, _ := pem.Decode([]byte(data))
	cert, _ := x509.ParseCertificate(block.Bytes)
	serialnumber := utils.InsertNth(utils.ToHexInt(cert.SerialNumber), 2)
	_ = s.casDb.InsertCert(ctx, caName, serialnumber)
	return certs, nil
}
