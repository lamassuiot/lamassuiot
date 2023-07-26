package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
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
	ImportCA(ctx context.Context, input *api.ImportCAInput) (*api.ImportCAOutput, error)

	Verify(ctx context.Context, input *api.VerifyInput) (*api.VerifyOutput, error)
	Sign(ctx context.Context, input *api.SignInput) (*api.SignOutput, error)

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

	ScanAboutToExpireCertificates(ctx context.Context, input *api.ScanAboutToExpireCertificatesInput) (*api.ScanAboutToExpireCertificatesOutput, error)
	ScanExpiredAndOutOfSyncCertificates(ctx context.Context, input *api.ScanExpiredAndOutOfSyncCertificatesInput) (*api.ScanExpiredAndOutOfSyncCertificatesOutput, error)
}

type CAService struct {
	service               Service
	certificateRepository repository.Certificates
	engine                x509engines.X509Engine
	ocspServerURL         string
	cronInstance          *cron.Cron
	aboutToExpireDays     int
}

func NewCAService(engine x509engines.X509Engine, certificateRepository repository.Certificates, ocspServerURL string, aboutToExpireDays int, periodicScanEnabled bool, periodicScanCron string) Service {
	cronInstance := cron.New()

	svc := CAService{
		engine:                engine,
		certificateRepository: certificateRepository,
		ocspServerURL:         ocspServerURL,
		aboutToExpireDays:     aboutToExpireDays,
	}

	svc.service = &svc

	exists, _, err := svc.certificateRepository.SelectCAByName(context.Background(), api.CATypeDMSEnroller, "LAMASSU-DMS-MANAGER")
	if err != nil {
		log.Fatal("Could not detect provisioning status: ", err)
	}

	if !exists {
		issuanceDuration := time.Now().Add(time.Hour * 24 * 365 * 3)
		log.Info("Generating LAMASSU-DMS-MANAGER CA")
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
			CAExpiration:           time.Now().Add(time.Hour * 24 * 365 * 5),
			IssuanceExpirationDate: &issuanceDuration,
			IssuanceExpirationType: "DATE",
		})
	} else {
		log.Info("LAMASSU-DMS-MANAGER CA already provisioned")
	}

	if periodicScanEnabled {
		log.Info(fmt.Sprintf("Adding periodic scan funcion at [%s]", periodicScanCron))
		_, err := cronInstance.AddFunc(periodicScanCron, func() { // runs daily
			log.Info("Starting scan")
			output1, err := svc.ScanAboutToExpireCertificates(context.Background(), &api.ScanAboutToExpireCertificatesInput{})
			if err != nil {
				log.Error("Error while perfoming AboutToExpire scan: ", err)
			} else {
				log.Info(fmt.Sprintf("Total AboutToExpire scanned certificates: %d", output1.AboutToExpiredTotal))
			}

			output2, err := svc.ScanExpiredAndOutOfSyncCertificates(context.Background(), &api.ScanExpiredAndOutOfSyncCertificatesInput{})
			if err != nil {
				log.Error("Error while perfoming Expired scan: ", err)
			} else {
				log.Info(fmt.Sprintf("Total Expired scanned certificates: %d", output2.TotalExpired))
			}
		})
		if err != nil {
			log.Error("Could not add periodic scan function in cron service: ", err)
		}
	} else {
		log.Info("Periodic scann is disabled")
	}

	svc.cronInstance = cronInstance
	svc.cronInstance.Start()
	return &svc
}

func (s *CAService) SetService(service Service) {
	s.service = service
}

func (s *CAService) GetEngineProviderInfo() api.EngineProviderInfo {
	return s.engine.GetEngineConfig()
}

func (s *CAService) Health() bool {
	return true
}

func (s *CAService) Stats(ctx context.Context, input *api.GetStatsInput) (*api.GetStatsOutput, error) {
	stats := api.GetStatsOutput{
		IssuedCerts: 0,
		CAs:         0,
		ScanDate:    time.Now(),
	}

	s.service.IterateCAsWithPredicate(ctx, &api.IterateCAsWithPredicateInput{
		CAType: api.CATypePKI,
		PredicateFunc: func(c *api.CACertificate) {
			getCertificatesOutput, err := s.service.GetCertificates(ctx, &api.GetCertificatesInput{
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

func (s *CAService) DeleteCA(ctx context.Context, input *api.GetCAByNameInput) error {
	return nil
}

func (s *CAService) IterateCAsWithPredicate(ctx context.Context, input *api.IterateCAsWithPredicateInput) (*api.IterateCAsWithPredicateOutput, error) {
	var cas []api.CACertificate
	limit := 100
	i := 0

	for {
		casOutput, err := s.service.GetCAs(
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

func (s *CAService) GetCAByName(ctx context.Context, input *api.GetCAByNameInput) (*api.GetCAByNameOutput, error) {
	exists, ca, err := s.certificateRepository.SelectCAByName(ctx, input.CAType, input.CAName)
	if err != nil {
		return &api.GetCAByNameOutput{}, err
	}

	if !exists {
		return &api.GetCAByNameOutput{}, &caerrors.ResourceNotFoundError{
			ResourceType: "CA",
			ResourceId:   input.CAName,
		}
	}

	if ca.Certificate.Certificate.NotAfter.Before(time.Now()) {
		if ca.Status != api.StatusExpired && ca.Status != api.StatusRevoked {
			updateCAOutput, err := s.service.UpdateCAStatus(ctx, &api.UpdateCAStatusInput{
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

func (s *CAService) GetCAs(ctx context.Context, input *api.GetCAsInput) (*api.GetCAsOutput, error) {
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
				updateCAOutput, err := s.service.UpdateCAStatus(ctx, &api.UpdateCAStatusInput{
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

func (s *CAService) CreateCA(ctx context.Context, input *api.CreateCAInput) (*api.CreateCAOutput, error) {
	exits, _, err := s.certificateRepository.SelectCAByName(ctx, input.CAType, input.Subject.CommonName)
	if err != nil {
		return nil, err
	}

	if exits {
		return nil, &caerrors.DuplicateResourceError{
			ResourceType: "CA",
			ResourceId:   input.Subject.CommonName,
		}
	}

	caCertificate, err := s.engine.CreateCA(*input)
	if err != nil {
		log.Error("error while creating CA certificate: ", err)
		return nil, err
	}

	if input.IssuanceExpirationType == api.ExpirationTypeDate {
		input.IssuanceExpirationDuration = nil
	} else {
		input.IssuanceExpirationDate = nil
	}
	err = s.certificateRepository.InsertCA(ctx, input.CAType, caCertificate, input.IssuanceExpirationDate, input.IssuanceExpirationDuration, string(input.IssuanceExpirationType), true)
	if err != nil {
		log.Error(err)
		return &api.CreateCAOutput{}, err
	}

	_, ca, err := s.certificateRepository.SelectCAByName(ctx, input.CAType, input.Subject.CommonName)
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

func (s *CAService) ImportCA(ctx context.Context, input *api.ImportCAInput) (*api.ImportCAOutput, error) {
	exits, _, err := s.certificateRepository.SelectCAByName(ctx, input.CAType, input.Certificate.Subject.CommonName)
	if err != nil {
		return nil, err
	}

	if exits {
		return nil, &caerrors.DuplicateResourceError{
			ResourceType: "CA",
			ResourceId:   input.Certificate.Subject.CommonName,
		}
	}
	if !input.WithPrivateKey {
		err = s.certificateRepository.InsertCA(ctx, input.CAType, input.Certificate, nil, nil, "", input.WithPrivateKey)
		if err != nil {
			log.Error(err)
			return &api.ImportCAOutput{}, err
		}
	} else {
		if input.IssuanceExpirationType == api.ExpirationTypeDate {
			input.IssuanceExpirationDuration = nil
		} else {
			input.IssuanceExpirationDate = nil
		}
		err = s.engine.ImportCA(*input.PrivateKey, input.Certificate.Subject.CommonName)
		if err != nil {
			log.Error(err)
			return &api.ImportCAOutput{}, err
		}
		err = s.certificateRepository.InsertCA(ctx, input.CAType, input.Certificate, input.IssuanceExpirationDate, input.IssuanceExpirationDuration, string(input.IssuanceExpirationType), input.WithPrivateKey)
		if err != nil {
			log.Error(err)
			return &api.ImportCAOutput{}, err
		}
	}
	_, ca, err := s.certificateRepository.SelectCAByName(ctx, input.CAType, input.Certificate.Subject.CommonName)
	if err != nil {
		log.Error(err)
		return &api.ImportCAOutput{}, err
	}

	keyType, keySize, keyStrength := getPublicKeyInfo(ca.Certificate.Certificate)
	ca.KeyMetadata = api.KeyStrengthMetadata{
		KeyType:     keyType,
		KeyBits:     keySize,
		KeyStrength: keyStrength,
	}
	return &api.ImportCAOutput{
		CACertificate: ca,
	}, nil
}

func (s *CAService) UpdateCAStatus(ctx context.Context, input *api.UpdateCAStatusInput) (*api.UpdateCAStatusOutput, error) {
	exits, _, err := s.certificateRepository.SelectCAByName(ctx, input.CAType, input.CAName)
	if err != nil {
		return nil, err
	}

	if !exits {
		return nil, &caerrors.ResourceNotFoundError{
			ResourceType: "CA",
			ResourceId:   input.CAName,
		}
	}

	switch input.Status {
	case api.StatusRevoked:
		_, err := s.service.RevokeCA(ctx, &api.RevokeCAInput{
			CAType: input.CAType,
			CAName: input.CAName,
		})
		if err != nil {
			return nil, err
		}
	default:
		err := s.certificateRepository.UpdateCAStatus(ctx, input.CAType, input.CAName, input.Status, "")
		if err != nil {
			return nil, err
		}
	}

	outputCertificate, _ := s.service.GetCAByName(ctx, &api.GetCAByNameInput{
		CAType: input.CAType,
		CAName: input.CAName,
	})

	return &api.UpdateCAStatusOutput{
		CACertificate: outputCertificate.CACertificate,
	}, nil
}

func (s *CAService) RevokeCA(ctx context.Context, input *api.RevokeCAInput) (*api.RevokeCAOutput, error) {
	exits, _, err := s.certificateRepository.SelectCAByName(ctx, input.CAType, input.CAName)
	if err != nil {
		return nil, err
	}

	if !exits {
		return nil, &caerrors.ResourceNotFoundError{
			ResourceType: "CA",
			ResourceId:   input.CAName,
		}
	}

	outputCAs, err := s.service.GetCAByName(ctx, &api.GetCAByNameInput{
		CAType: input.CAType,
		CAName: input.CAName,
	})
	if err != nil {
		return &api.RevokeCAOutput{}, err
	}

	if outputCAs.Status == api.StatusRevoked {
		return &api.RevokeCAOutput{}, errors.New(caerrors.ErrAlreadyRevoked)
	}

	err = s.certificateRepository.UpdateCAStatus(ctx, input.CAType, input.CAName, api.StatusRevoked, input.RevocationReason)
	if err != nil {
		return &api.RevokeCAOutput{}, err
	}

	s.service.IterateCertificatesWithPredicate(ctx, &api.IterateCertificatesWithPredicateInput{
		CAType: input.CAType,
		CAName: input.CAName,
		PredicateFunc: func(c *api.Certificate) {
			_, err := s.service.RevokeCertificate(ctx, &api.RevokeCertificateInput{
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

	outputCAs, _ = s.service.GetCAByName(ctx, &api.GetCAByNameInput{
		CAType: input.CAType,
		CAName: input.CAName,
	})
	return &api.RevokeCAOutput{
		CACertificate: outputCAs.CACertificate,
	}, nil
}

func (s *CAService) GetCertificates(ctx context.Context, input *api.GetCertificatesInput) (*api.GetCertificatesOutput, error) {
	output := api.GetCertificatesOutput{}

	if input.QueryParameters.Pagination.Limit == 0 {
		input.QueryParameters.Pagination.Limit = 100
	}

	exists, _, err := s.certificateRepository.SelectCAByName(ctx, input.CAType, input.CAName)
	if err != nil {
		return &output, err
	}

	if !exists {
		return nil, &caerrors.ResourceNotFoundError{
			ResourceType: "CA",
			ResourceId:   input.CAName,
		}
	}

	totalCertificates, certificates, err := s.certificateRepository.SelectCertificatesByCA(ctx, input.CAType, input.CAName, input.QueryParameters)
	if err != nil {
		return &output, err
	}

	for i, c := range certificates {
		if c.Certificate.NotAfter.Before(time.Now()) {
			if c.Status != api.StatusExpired && c.Status != api.StatusRevoked {
				updateCertificateOutput, err := s.service.UpdateCertificateStatus(ctx, &api.UpdateCertificateStatusInput{
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

func (s *CAService) GetCertificateBySerialNumber(ctx context.Context, input *api.GetCertificateBySerialNumberInput) (*api.GetCertificateBySerialNumberOutput, error) {
	exists, certificate, err := s.certificateRepository.SelectCertificateBySerialNumber(ctx, input.CAType, input.CAName, input.CertificateSerialNumber)
	if err != nil {
		return &api.GetCertificateBySerialNumberOutput{}, err
	}

	if !exists {
		return nil, &caerrors.ResourceNotFoundError{
			ResourceType: "Certificate",
			ResourceId:   input.CertificateSerialNumber,
		}
	}

	if certificate.Certificate.NotAfter.Before(time.Now()) {
		if certificate.Status != api.StatusExpired && certificate.Status != api.StatusRevoked {
			updateCertificateOutput, err := s.service.UpdateCertificateStatus(ctx, &api.UpdateCertificateStatusInput{
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

func (s *CAService) UpdateCertificateStatus(ctx context.Context, input *api.UpdateCertificateStatusInput) (*api.UpdateCertificateStatusOutput, error) {
	switch input.Status {
	case api.StatusRevoked:
		_, err := s.service.RevokeCertificate(ctx, &api.RevokeCertificateInput{
			CAType:                  input.CAType,
			CAName:                  input.CAName,
			CertificateSerialNumber: input.CertificateSerialNumber,
		})
		if err != nil {
			return nil, err
		}
	default:
		err := s.certificateRepository.UpdateCertificateStatus(ctx, input.CAType, input.CAName, input.CertificateSerialNumber, input.Status, "")
		if err != nil {
			return nil, err
		}
	}

	outputCertificate, _ := s.service.GetCertificateBySerialNumber(ctx, &api.GetCertificateBySerialNumberInput{
		CAType:                  input.CAType,
		CAName:                  input.CAName,
		CertificateSerialNumber: input.CertificateSerialNumber,
	})

	return &api.UpdateCertificateStatusOutput{
		Certificate: outputCertificate.Certificate,
	}, nil
}

func (s *CAService) RevokeCertificate(ctx context.Context, input *api.RevokeCertificateInput) (*api.RevokeCertificateOutput, error) {
	outputCertificate, err := s.service.GetCertificateBySerialNumber(ctx, &api.GetCertificateBySerialNumberInput{
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

	outputCertificate, _ = s.service.GetCertificateBySerialNumber(ctx, &api.GetCertificateBySerialNumberInput{
		CAType:                  input.CAType,
		CAName:                  input.CAName,
		CertificateSerialNumber: input.CertificateSerialNumber,
	})

	return &api.RevokeCertificateOutput{
		Certificate: outputCertificate.Certificate,
	}, nil
}

func (s *CAService) SignCertificateRequest(ctx context.Context, input *api.SignCertificateRequestInput) (*api.SignCertificateRequestOutput, error) {
	caOutput, err := s.service.GetCAByName(ctx, &api.GetCAByNameInput{
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
	var certificateExpiration time.Time
	if caOutput.CACertificate.IssuanceType == "DATE" {
		certificateExpiration = *caOutput.CACertificate.IssuanceDate
	} else {
		certificateExpiration = time.Now().Add(*caOutput.CACertificate.IssuanceDuration * time.Second)
	}
	certificate, err := s.engine.SignCertificateRequest(caOutput.Certificate.Certificate, certificateExpiration, input)
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

func (s *CAService) GetCertificatesAboutToExpire(ctx context.Context, input *api.GetCertificatesAboutToExpireInput) (*api.GetCertificatesAboutToExpireOutput, error) {
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

func (s *CAService) GetExpiredAndOutOfSyncCertificates(ctx context.Context, input *api.GetExpiredAndOutOfSyncCertificatesInput) (*api.GetExpiredAndOutOfSyncCertificatesOutput, error) {
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

func (s *CAService) Sign(ctx context.Context, input *api.SignInput) (*api.SignOutput, error) {
	ca, err := s.service.GetCAByName(ctx, &api.GetCAByNameInput{
		CAType: api.CATypePKI,
		CAName: input.CaName,
	})
	if err != nil {
		return &api.SignOutput{}, err
	}

	signature, err := s.engine.Sign(ca.CACertificate.Certificate, input.Message, string(input.MessageType), string(input.SigningAlgorithm))
	if err != nil {
		return &api.SignOutput{}, err
	}

	return &api.SignOutput{
		Signature:        base64.StdEncoding.EncodeToString(signature),
		SigningAlgorithm: input.SigningAlgorithm,
	}, nil
}

func (s *CAService) Verify(ctx context.Context, input *api.VerifyInput) (*api.VerifyOutput, error) {
	ca, err := s.service.GetCAByName(ctx, &api.GetCAByNameInput{
		CAType: api.CATypePKI,
		CAName: input.CaName,
	})

	if err != nil {
		return &api.VerifyOutput{}, err
	}

	verification, err := s.engine.Verify(ca.CACertificate.Certificate, input.Signature, input.Message, string(input.MessageType), string(input.SigningAlgorithm))
	if err != nil {
		return &api.VerifyOutput{}, err
	}
	return &api.VerifyOutput{
		VerificationResult: verification,
	}, nil
}

func (s *CAService) IterateCertificatesWithPredicate(ctx context.Context, input *api.IterateCertificatesWithPredicateInput) (*api.IterateCertificatesWithPredicateOutput, error) {
	output := api.IterateCertificatesWithPredicateOutput{}

	var certificates []api.Certificate
	limit := 100
	i := 0

	for {
		certsOutput, err := s.service.GetCertificates(ctx, &api.GetCertificatesInput{
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

func (s *CAService) ScanAboutToExpireCertificates(ctx context.Context, input *api.ScanAboutToExpireCertificatesInput) (*api.ScanAboutToExpireCertificatesOutput, error) {
	limit := 100
	i := 0
	total := 0

	for {
		getCertificatesOutput, err := s.service.GetCertificatesAboutToExpire(ctx, &api.GetCertificatesAboutToExpireInput{
			QueryParameters: common.QueryParameters{
				Pagination: common.PaginationOptions{
					Limit:  limit,
					Offset: i * limit,
				},
			},
		})
		if err != nil {
			return nil, err
		}

		total = getCertificatesOutput.TotalCertificates

		if len(getCertificatesOutput.Certificates) == 0 {
			break
		}

		i++

		for _, cert := range getCertificatesOutput.Certificates {
			s.service.UpdateCertificateStatus(ctx, &api.UpdateCertificateStatusInput{
				CAType:                  cert.CAType,
				CAName:                  cert.CAName,
				CertificateSerialNumber: cert.SerialNumber,
				Status:                  api.StatusAboutToExpire,
			})
		}
	}

	return &api.ScanAboutToExpireCertificatesOutput{
		AboutToExpiredTotal: total,
	}, nil
}

func (s *CAService) ScanExpiredAndOutOfSyncCertificates(ctx context.Context, input *api.ScanExpiredAndOutOfSyncCertificatesInput) (*api.ScanExpiredAndOutOfSyncCertificatesOutput, error) {
	limit := 100
	i := 0
	total := 0

	for {
		getCertificatesOutput, err := s.service.GetExpiredAndOutOfSyncCertificates(ctx, &api.GetExpiredAndOutOfSyncCertificatesInput{
			QueryParameters: common.QueryParameters{
				Pagination: common.PaginationOptions{
					Limit:  limit,
					Offset: i * limit,
				},
			},
		})

		total = getCertificatesOutput.TotalCertificates

		if err != nil {
			return nil, err
		}
		if len(getCertificatesOutput.Certificates) == 0 {
			break
		}

		i++

		for _, cert := range getCertificatesOutput.Certificates {
			s.service.UpdateCertificateStatus(ctx, &api.UpdateCertificateStatusInput{
				CAType:                  cert.CAType,
				CAName:                  cert.CAName,
				CertificateSerialNumber: cert.SerialNumber,
				Status:                  api.StatusExpired,
			})
		}
	}

	return &api.ScanExpiredAndOutOfSyncCertificatesOutput{
		TotalExpired: total,
	}, nil
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
