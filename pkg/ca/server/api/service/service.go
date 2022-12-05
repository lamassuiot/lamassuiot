package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	caerrors "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/repository"
	x509engines "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service/x509-engines"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
	"github.com/robfig/cron/v3"
	log "github.com/sirupsen/logrus"
)

type Service interface {
	Health() bool
	GetEngineProviderInfo() api.EngineProviderInfo
	Stats(ctx context.Context, input *api.GetStatsInput) (*api.GetStatsOutput, error)

	CreateCA(ctx context.Context, input *api.CreateCAInput) (*api.CreateCAOutput, error)
	GetCAs(ctx context.Context, input *api.GetCAsInput) (*api.GetCAsOutput, error)
	GetCAByName(ctx context.Context, input *api.GetCAByNameInput) (*api.GetCAByNameOutput, error)
	// ImportCA(ctx context.Context, input *api.ImportCAInput) (*api.ImportCAOutput, error)

	UpdateCAStatus(ctx context.Context, input *api.UpdateCAStatusInput) (*api.UpdateCAStatusOutput, error)
	RevokeCA(ctx context.Context, input *api.RevokeCAInput) (*api.RevokeCAOutput, error)

	IterateCAsWithPredicate(ctx context.Context, input *api.IterateCAsWithPredicateInput) (*api.IterateCAsWithPredicateOutput, error)

	SignCertificateRequest(ctx context.Context, input *api.SignCertificateRequestInput) (*api.SignCertificateRequestOutput, error)
	RevokeCertificate(ctx context.Context, input *api.RevokeCertificateInput) (*api.RevokeCertificateOutput, error)
	UpdateCertificateStatus(ctx context.Context, input *api.UpdateCertificateStatusInput) (*api.UpdateCertificateStatusOutput, error)

	GetCertificateBySerialNumber(ctx context.Context, input *api.GetCertificateBySerialNumberInput) (*api.GetCertificateBySerialNumberOutput, error)
	GetCertificates(ctx context.Context, input *api.GetCertificatesInput) (*api.GetCertificatesOutput, error)
	GetCertificatesAboutToExpire(ctx context.Context, input *api.GetCertificatesAboutToExpireInput) (*api.GetCertificatesAboutToExpireOutput, error)
	GetExpiredAndOutOfSyncCertificates(ctx context.Context, input *api.GetExpiredAndOutOfSyncCertificatesInput) (*api.GetExpiredAndOutOfSyncCertificatesOutput, error)
	IterateCertificatesWithPredicate(ctx context.Context, input *api.IterateCertificatesWithPredicateInput) (*api.IterateCertificatesWithPredicateOutput, error)
}

type caService struct {
	certificateRepository repository.Certificates
	engine                x509engines.X509Engine
	ocspServerURL         string
	cronInstance          *cron.Cron
	aboutToExpireDays     int
}

func NewCAService(engine x509engines.X509Engine, certificateRepository repository.Certificates, ocspServerURL string, aboutToExpireDays int) Service {
	cronInstance := cron.New()

	svc := caService{
		engine:                engine,
		certificateRepository: certificateRepository,
		ocspServerURL:         ocspServerURL,
		aboutToExpireDays:     aboutToExpireDays,
	}

	_, err := svc.GetCAByName(context.Background(), &api.GetCAByNameInput{
		CAType: api.CATypeDMSEnroller,
		CAName: "LAMASSU-DMS-MANAGER",
	})

	if err != nil {
		log.Warn("Failed to get LAMASSU-DMS-MANAGER. Generating LAMASSU-DMS-MANAGER CA")
		svc.CreateCA(context.Background(), &api.CreateCAInput{
			CAType: api.CATypeDMSEnroller,
			Subject: api.Subject{
				CommonName:   "LAMASSU-DMS-MANAGER",
				Organization: "lamassu",
			},
			KeyMetadata: api.KeyMetadata{
				KeyType: api.KeyType(engine.GetEngineConfig().SupportedKeyTypes[0].Type),
				KeyBits: engine.GetEngineConfig().SupportedKeyTypes[0].MaximumSize,
			},
			CADuration:       time.Hour * 24 * 365 * 5,
			IssuanceDuration: time.Hour * 24 * 365 * 3,
		})
	}

	svc.cronInstance = cronInstance
	return &svc
}

func (s *caService) GetEngineProviderInfo() api.EngineProviderInfo {
	return s.engine.GetEngineConfig()
}

func (s *caService) Health() bool {
	return true
}

func (s *caService) Stats(ctx context.Context, input *api.GetStatsInput) (*api.GetStatsOutput, error) {
	stats := api.GetStatsOutput{
		IssuedCerts: 0,
		CAs:         0,
		ScanDate:    time.Now(),
	}

	s.IterateCAsWithPredicate(ctx, &api.IterateCAsWithPredicateInput{
		CAType: api.CATypePKI,
		PredicateFunc: func(c *api.CACertificate) {
			getCertificatesOutput, err := s.GetCertificates(ctx, &api.GetCertificatesInput{
				CAType: api.CATypePKI,
				CAName: c.CAName,
			})
			if err != nil {
				return
			}

			stats.CAs++
			stats.IssuedCerts += getCertificatesOutput.TotalCertificates
		},
	})
	return &stats, nil
}

func (s *caService) DeleteCA(ctx context.Context, input *api.GetCAByNameInput) error {
	return nil
}

func (s *caService) IterateCAsWithPredicate(ctx context.Context, input *api.IterateCAsWithPredicateInput) (*api.IterateCAsWithPredicateOutput, error) {
	var cas []api.CACertificate
	limit := 100
	i := 0

	for {
		casOutput, err := s.GetCAs(
			ctx,
			&api.GetCAsInput{
				CAType: input.CAType,
				QueryParameters: common.QueryParameters{
					Pagination: common.PaginationOptions{
						Limit:  i,
						Offset: i * limit,
					},
				},
			},
		)
		if err != nil {
			return &api.IterateCAsWithPredicateOutput{}, err
		}

		if len(casOutput.CAs) == 0 {
			break
		}

		cas = append(cas, casOutput.CAs...)
		i++
	}

	for _, ca := range cas {
		input.PredicateFunc(&ca)
	}

	return &api.IterateCAsWithPredicateOutput{}, nil
}

func (s *caService) GetCAByName(ctx context.Context, input *api.GetCAByNameInput) (*api.GetCAByNameOutput, error) {
	ca, err := s.certificateRepository.SelectCAByName(ctx, input.CAType, input.CAName)
	if err != nil {
		return &api.GetCAByNameOutput{}, err
	}

	if ca.Certificate.Certificate.NotAfter.Before(time.Now()) {
		if ca.Status != api.StatusExpired && ca.Status != api.StatusRevoked {
			updateCAOutput, err := s.UpdateCAStatus(ctx, &api.UpdateCAStatusInput{
				CAType: api.CATypePKI,
				CAName: ca.CAName,
				Status: api.StatusExpired,
			})
			if err != nil {
				log.Errorf("Could not update the status of an expired CA status "+ca.CAName, err)
				return &api.GetCAByNameOutput{}, err
			}
			ca = updateCAOutput.CACertificate
		}
	}

	keyType, keySize, keyStrength := getPublicKeyInfo(ca.Certificate.Certificate)
	ca.KeyMetadata = api.KeyStrengthMetadata{
		KeyType:     keyType,
		KeyBits:     keySize,
		KeyStrength: keyStrength,
	}

	return &api.GetCAByNameOutput{
		CACertificate: ca,
	}, nil
}

func (s *caService) GetCAs(ctx context.Context, input *api.GetCAsInput) (*api.GetCAsOutput, error) {
	output := api.GetCAsOutput{}

	if input.QueryParameters.Pagination.Limit == 0 {
		input.QueryParameters.Pagination.Limit = 100
	}

	totalCAs, CAs, err := s.certificateRepository.SelectCAs(ctx, api.CATypePKI, input.QueryParameters)
	if err != nil {
		return &output, err
	}

	for i, ca := range CAs {
		if ca.Certificate.Certificate.NotAfter.Before(time.Now()) {
			if ca.Status != api.StatusExpired && ca.Status != api.StatusRevoked {
				updateCAOutput, err := s.UpdateCAStatus(ctx, &api.UpdateCAStatusInput{
					CAType: api.CATypePKI,
					CAName: ca.CAName,
					Status: api.StatusExpired,
				})
				if err != nil {
					log.Error(fmt.Sprintf("Could not update the status of an expired CA [%s] status: ", ca.CAName), err)
					continue
				}
				CAs[i] = updateCAOutput.CACertificate
			}
		}

		keyType, keySize, keyStrength := getPublicKeyInfo(ca.Certificate.Certificate)
		CAs[i].KeyMetadata = api.KeyStrengthMetadata{
			KeyType:     keyType,
			KeyBits:     keySize,
			KeyStrength: keyStrength,
		}
	}

	output = api.GetCAsOutput{
		TotalCAs: totalCAs,
		CAs:      CAs,
	}

	return &output, err

}

func (s *caService) CreateCA(ctx context.Context, input *api.CreateCAInput) (*api.CreateCAOutput, error) {
	_, err := s.GetCAByName(ctx, &api.GetCAByNameInput{
		CAType: input.CAType,
		CAName: input.Subject.CommonName,
	})

	if err != nil {
		switch err.(type) {
		case *caerrors.ResourceNotFoundError:
			// OK
			break
		default:
			return &api.CreateCAOutput{}, err
		}
	} else {
		return &api.CreateCAOutput{}, &caerrors.DuplicateResourceError{
			ResourceType: "CA",
			ResourceId:   input.Subject.CommonName,
		}
	}

	caCertificate, err := s.engine.CreateCA(*input)
	if err != nil {
		log.Error("error while creating CA certificate: ", err)
		return nil, err
	}

	err = s.certificateRepository.InsertCA(ctx, input.CAType, caCertificate, input.IssuanceDuration)
	if err != nil {
		log.Error(err)
		return &api.CreateCAOutput{}, err
	}

	ca, err := s.certificateRepository.SelectCAByName(ctx, input.CAType, input.Subject.CommonName)
	if err != nil {
		log.Error(err)
		return &api.CreateCAOutput{}, err
	}

	keyType, keySize, keyStrength := getPublicKeyInfo(ca.Certificate.Certificate)
	ca.KeyMetadata = api.KeyStrengthMetadata{
		KeyType:     keyType,
		KeyBits:     keySize,
		KeyStrength: keyStrength,
	}

	return &api.CreateCAOutput{
		CACertificate: ca,
	}, nil
}

// func (s *caService) ImportCA(ctx context.Context, input *api.ImportCAInput) (*api.ImportCAOutput, error) {
// 	return s.secrets.ImportCA(input)
// }

func (s *caService) UpdateCAStatus(ctx context.Context, input *api.UpdateCAStatusInput) (*api.UpdateCAStatusOutput, error) {
	switch input.Status {
	case api.StatusRevoked:
		s.RevokeCA(ctx, &api.RevokeCAInput{
			CAType: input.CAType,
			CAName: input.CAName,
		})
	default:
		s.certificateRepository.UpdateCAStatus(ctx, input.CAType, input.CAName, input.Status, "")
	}

	outputCertificate, _ := s.GetCAByName(ctx, &api.GetCAByNameInput{
		CAType: input.CAType,
		CAName: input.CAName,
	})

	return &api.UpdateCAStatusOutput{
		CACertificate: outputCertificate.CACertificate,
	}, nil
}

func (s *caService) RevokeCA(ctx context.Context, input *api.RevokeCAInput) (*api.RevokeCAOutput, error) {
	outputCAs, err := s.GetCAByName(ctx, &api.GetCAByNameInput{
		CAType: input.CAType,
		CAName: input.CAName,
	})

	if outputCAs.Status == api.StatusRevoked {
		return &api.RevokeCAOutput{}, errors.New(caerrors.ErrAlreadyRevoked)
	}

	if err != nil {
		return &api.RevokeCAOutput{}, err
	}

	err = s.certificateRepository.UpdateCAStatus(ctx, input.CAType, input.CAName, api.StatusRevoked, input.RevocationReason)
	if err != nil {
		return &api.RevokeCAOutput{}, err
	}

	s.IterateCertificatesWithPredicate(ctx, &api.IterateCertificatesWithPredicateInput{
		CAType: input.CAType,
		CAName: input.CAName,
		PredicateFunc: func(c *api.Certificate) {
			_, err := s.RevokeCertificate(ctx, &api.RevokeCertificateInput{
				CAType:                  input.CAType,
				CAName:                  input.CAName,
				CertificateSerialNumber: c.SerialNumber,
				RevocationReason:        "Automatic revocation due to CA revocation",
			})
			if err != nil {
				fmt.Println(err)
			}
		},
	})

	outputCAs, _ = s.GetCAByName(ctx, &api.GetCAByNameInput{
		CAType: input.CAType,
		CAName: input.CAName,
	})
	return &api.RevokeCAOutput{
		CACertificate: outputCAs.CACertificate,
	}, nil
}

func (s *caService) GetCertificates(ctx context.Context, input *api.GetCertificatesInput) (*api.GetCertificatesOutput, error) {
	output := api.GetCertificatesOutput{}

	if input.QueryParameters.Pagination.Limit == 0 {
		input.QueryParameters.Pagination.Limit = 100
	}

	_, err := s.certificateRepository.SelectCAByName(ctx, input.CAType, input.CAName)
	if err != nil {
		return &output, err
	}

	totalCertificates, certificates, err := s.certificateRepository.SelectCertificatesByCA(ctx, input.CAType, input.CAName, input.QueryParameters)
	if err != nil {
		return &output, err
	}

	for i, c := range certificates {
		if c.Certificate.NotAfter.Before(time.Now()) {
			if c.Status != api.StatusExpired && c.Status != api.StatusRevoked {
				updateCertificateOutput, err := s.UpdateCertificateStatus(ctx, &api.UpdateCertificateStatusInput{
					CAType:                  input.CAType,
					CAName:                  c.CAName,
					CertificateSerialNumber: c.SerialNumber,
					Status:                  api.StatusExpired,
				})
				if err != nil {
					log.Errorf(fmt.Sprintf("Could not update the status of an expired Certificate status. CA [%s] SerialNumber [%s]: ", c.CAName, c.SerialNumber), err)
					return &api.GetCertificatesOutput{}, err
				}
				certificates[i] = updateCertificateOutput.Certificate
			}
		}

		keyType, keySize, keyStrength := getPublicKeyInfo(c.Certificate)
		certificates[i].KeyMetadata = api.KeyStrengthMetadata{
			KeyType:     keyType,
			KeyBits:     keySize,
			KeyStrength: keyStrength,
		}
	}

	output = api.GetCertificatesOutput{
		TotalCertificates: totalCertificates,
		Certificates:      certificates,
	}

	return &output, err
}

func (s *caService) GetCertificateBySerialNumber(ctx context.Context, input *api.GetCertificateBySerialNumberInput) (*api.GetCertificateBySerialNumberOutput, error) {
	certificate, err := s.certificateRepository.SelectCertificateBySerialNumber(ctx, input.CAType, input.CAName, input.CertificateSerialNumber)
	if err != nil {
		return &api.GetCertificateBySerialNumberOutput{}, err
	}

	if certificate.Certificate.NotAfter.Before(time.Now()) {
		if certificate.Status != api.StatusExpired && certificate.Status != api.StatusRevoked {
			updateCertificateOutput, err := s.UpdateCertificateStatus(ctx, &api.UpdateCertificateStatusInput{
				CAType:                  input.CAType,
				CAName:                  certificate.CAName,
				CertificateSerialNumber: certificate.SerialNumber,
				Status:                  api.StatusExpired,
			})
			if err != nil {
				log.Errorf(fmt.Sprintf("Could not update the status of an expired Certificate status. CA [%s] SerialNumber [%s]: ", certificate.CAName, certificate.SerialNumber), err)
				return &api.GetCertificateBySerialNumberOutput{}, err
			}
			certificate = updateCertificateOutput.Certificate
		}
	}

	keyType, keySize, keyStrength := getPublicKeyInfo(certificate.Certificate)
	certificate.KeyMetadata = api.KeyStrengthMetadata{
		KeyType:     keyType,
		KeyBits:     keySize,
		KeyStrength: keyStrength,
	}

	return &api.GetCertificateBySerialNumberOutput{
		Certificate: certificate,
	}, nil
}

func (s *caService) UpdateCertificateStatus(ctx context.Context, input *api.UpdateCertificateStatusInput) (*api.UpdateCertificateStatusOutput, error) {
	switch input.Status {
	case api.StatusRevoked:
		s.RevokeCertificate(ctx, &api.RevokeCertificateInput{
			CAType:                  input.CAType,
			CAName:                  input.CAName,
			CertificateSerialNumber: input.CertificateSerialNumber,
		})
	default:
		s.certificateRepository.UpdateCertificateStatus(ctx, input.CAType, input.CAName, input.CertificateSerialNumber, input.Status, "")
	}

	outputCertificate, _ := s.GetCertificateBySerialNumber(ctx, &api.GetCertificateBySerialNumberInput{
		CAType:                  input.CAType,
		CAName:                  input.CAName,
		CertificateSerialNumber: input.CertificateSerialNumber,
	})

	return &api.UpdateCertificateStatusOutput{
		Certificate: outputCertificate.Certificate,
	}, nil
}

func (s *caService) RevokeCertificate(ctx context.Context, input *api.RevokeCertificateInput) (*api.RevokeCertificateOutput, error) {
	outputCertificate, err := s.GetCertificateBySerialNumber(ctx, &api.GetCertificateBySerialNumberInput{
		CAType:                  input.CAType,
		CAName:                  input.CAName,
		CertificateSerialNumber: input.CertificateSerialNumber,
	})
	if err != nil {
		return &api.RevokeCertificateOutput{}, err
	}

	if outputCertificate.Status == api.StatusRevoked {
		return &api.RevokeCertificateOutput{}, errors.New(caerrors.ErrAlreadyRevoked)
	}

	if err != nil {
		return &api.RevokeCertificateOutput{}, err
	}

	err = s.certificateRepository.UpdateCertificateStatus(ctx, input.CAType, input.CAName, input.CertificateSerialNumber, api.StatusRevoked, input.RevocationReason)
	if err != nil {
		return &api.RevokeCertificateOutput{}, err
	}

	outputCertificate, _ = s.GetCertificateBySerialNumber(ctx, &api.GetCertificateBySerialNumberInput{
		CAType:                  input.CAType,
		CAName:                  input.CAName,
		CertificateSerialNumber: input.CertificateSerialNumber,
	})

	return &api.RevokeCertificateOutput{
		Certificate: outputCertificate.Certificate,
	}, nil
}

func (s *caService) SignCertificateRequest(ctx context.Context, input *api.SignCertificateRequestInput) (*api.SignCertificateRequestOutput, error) {
	caOutput, err := s.GetCAByName(ctx, &api.GetCAByNameInput{
		CAType: input.CAType,
		CAName: input.CAName,
	})
	if err != nil {
		log.Error(err)
		return &api.SignCertificateRequestOutput{}, err
	}

	if caOutput.Status == api.StatusExpired || caOutput.Status == api.StatusRevoked {
		return &api.SignCertificateRequestOutput{}, errors.New("CA is expired or revoked")
	}

	certificate, err := s.engine.SignCertificateRequest(caOutput.Certificate.Certificate, caOutput.IssuanceDuration, input)
	if err != nil {
		log.Error("Could not sign certificate request: ", err)
		return &api.SignCertificateRequestOutput{}, err
	}

	err = s.certificateRepository.InsertCertificate(ctx, input.CAType, input.CAName, certificate)
	if err != nil {
		log.Error(err)
		return &api.SignCertificateRequestOutput{}, err
	}

	return &api.SignCertificateRequestOutput{
		Certificate:   certificate,
		CACertificate: caOutput.Certificate.Certificate,
	}, nil

}

func (s *caService) GetCertificatesAboutToExpire(ctx context.Context, input *api.GetCertificatesAboutToExpireInput) (*api.GetCertificatesAboutToExpireOutput, error) {
	totalAboutToExpire, certs, err := s.certificateRepository.SelectAboutToExpireCertificates(ctx, time.Duration(s.aboutToExpireDays*int(time.Hour)*24), common.QueryParameters{
		Pagination: input.QueryParameters.Pagination,
	})

	if err != nil {
		return nil, err
	}

	return &api.GetCertificatesAboutToExpireOutput{
		Certificates:      certs,
		TotalCertificates: totalAboutToExpire,
	}, nil
}

func (s *caService) GetExpiredAndOutOfSyncCertificates(ctx context.Context, input *api.GetExpiredAndOutOfSyncCertificatesInput) (*api.GetExpiredAndOutOfSyncCertificatesOutput, error) {
	totalExpiredCertificates, certs, err := s.certificateRepository.ScanExpiredAndOutOfSyncCertificates(ctx, time.Now(), common.QueryParameters{
		Pagination: input.QueryParameters.Pagination,
	})

	if err != nil {
		return nil, err
	}

	return &api.GetExpiredAndOutOfSyncCertificatesOutput{
		Certificates:      certs,
		TotalCertificates: totalExpiredCertificates,
	}, nil
}

func (s *caService) IterateCertificatesWithPredicate(ctx context.Context, input *api.IterateCertificatesWithPredicateInput) (*api.IterateCertificatesWithPredicateOutput, error) {
	output := api.IterateCertificatesWithPredicateOutput{}

	var certificates []api.Certificate
	limit := 100
	i := 0

	for {
		certsOutput, err := s.GetCertificates(ctx, &api.GetCertificatesInput{
			CAType: input.CAType,
			CAName: input.CAName,
			QueryParameters: common.QueryParameters{
				Pagination: common.PaginationOptions{
					Limit:  limit,
					Offset: i * limit,
				},
			},
		})
		if err != nil {
			return &output, err
		}
		if len(certsOutput.Certificates) == 0 {
			break
		}

		certificates = append(certificates, certsOutput.Certificates...)
		i++
	}

	for _, v := range certificates {
		input.PredicateFunc(&v)
	}

	return &output, nil
}

func getPublicKeyInfo(cert *x509.Certificate) (api.KeyType, int, api.KeyStrength) {
	key := api.ParseKeyType(cert.PublicKeyAlgorithm.String())
	var keyBits int
	switch key {
	case api.RSA:
		keyBits = cert.PublicKey.(*rsa.PublicKey).N.BitLen()
	case api.ECDSA:
		keyBits = cert.PublicKey.(*ecdsa.PublicKey).Params().BitSize
	}

	var keyStrength api.KeyStrength = api.KeyStrengthLow
	switch key {
	case api.RSA:
		if keyBits < 2048 {
			keyStrength = api.KeyStrengthLow
		} else if keyBits >= 2048 && keyBits < 3072 {
			keyStrength = api.KeyStrengthMedium
		} else {
			keyStrength = api.KeyStrengthHigh
		}
	case api.ECDSA:
		if keyBits <= 128 {
			keyStrength = api.KeyStrengthLow
		} else if keyBits > 128 && keyBits < 256 {
			keyStrength = api.KeyStrengthMedium
		} else {
			keyStrength = api.KeyStrengthHigh
		}
	}

	return key, keyBits, keyStrength
}
