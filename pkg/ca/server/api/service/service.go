package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	caerrors "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/repository"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
)

type CryptoEngine interface {
	GetEngineConfig() api.EngineProviderInfo
	// GetPrivateKeys() ([]crypto.Signer, error)
	// DeleteAllKeys() error
	GetPrivateKeyByID(string) (crypto.Signer, error)
	CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error)
	CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error)
}

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
	GetCertificateBySerialNumber(ctx context.Context, input *api.GetCertificateBySerialNumberInput) (*api.GetCertificateBySerialNumberOutput, error)
	GetCertificates(ctx context.Context, input *api.GetCertificatesInput) (*api.GetCertificatesOutput, error)
	UpdateCertificateStatus(ctx context.Context, input *api.UpdateCertificateStatusInput) (*api.UpdateCertificateStatusOutput, error)
	IterateCertificatesWithPredicate(ctx context.Context, input *api.IterateCertificatesWithPredicateInput) (*api.IterateCertificatesWithPredicateOutput, error)
}

type caService struct {
	logger                log.Logger
	certificateRepository repository.Certificates
	cryptoEngine          CryptoEngine
	ocspServerURL         string
}

func NewCAService(logger log.Logger, engine CryptoEngine, certificateRepository repository.Certificates, ocspServerURL string) Service {
	svc := caService{
		logger:                logger,
		cryptoEngine:          engine,
		certificateRepository: certificateRepository,
		ocspServerURL:         ocspServerURL,
	}

	_, err := svc.GetCAByName(context.Background(), &api.GetCAByNameInput{
		CAType: api.CATypeDMSEnroller,
		CAName: "LAMASSU-DMS-MANAGER",
	})

	if err != nil {
		level.Debug(logger).Log("msg", "failed to get LAMASSU-DMS-MANAGER", "err", err)
		level.Debug(logger).Log("msg", "Generating LAMASSU-DMS-MANAGER CA", "err", err)
		svc.CreateCA(context.Background(), &api.CreateCAInput{
			CAType: api.CATypeDMSEnroller,
			Subject: api.Subject{
				CommonName:   "LAMASSU-DMS-MANAGER",
				Organization: "lamassu",
			},
			KeyMetadata: api.KeyMetadata{
				KeyType: "RSA",
				KeyBits: 4096,
			},
			CADuration:       time.Hour * 24 * 365 * 5,
			IssuanceDuration: time.Hour * 24 * 365 * 3,
		})
	}

	return &svc
}

func (s *caService) GetEngineProviderInfo() api.EngineProviderInfo {
	return s.cryptoEngine.GetEngineConfig()
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
				level.Debug(s.logger).Log("err", err, "msg", "Could not update the status of an expired CA status: "+ca.CAName)
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
					level.Debug(s.logger).Log("err", err, "msg", "Could not update the status of an expired CA status: "+ca.CAName)
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
	var signer crypto.Signer
	var derBytes []byte
	var err error

	_, err = s.GetCAByName(ctx, &api.GetCAByNameInput{
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

	if api.KeyType(input.KeyMetadata.KeyType) == api.RSA {
		signer, err = s.cryptoEngine.CreateRSAPrivateKey(input.KeyMetadata.KeyBits, input.Subject.CommonName)
		if err != nil {
			level.Debug(s.logger).Log("err", err)
			return &api.CreateCAOutput{}, err
		}

	} else {
		var curve elliptic.Curve
		switch input.KeyMetadata.KeyBits {
		case 224:
			curve = elliptic.P224()
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return &api.CreateCAOutput{}, errors.New("unsuported key size for ECDSA key")
		}
		signer, err = s.cryptoEngine.CreateECDSAPrivateKey(curve, input.Subject.CommonName)
		if err != nil {
			level.Debug(s.logger).Log("err", err)
			return &api.CreateCAOutput{}, err
		}
	}

	now := time.Now()
	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))

	templateCA := x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:         input.Subject.CommonName,
			Country:            []string{input.Subject.Country},
			Province:           []string{input.Subject.State},
			Locality:           []string{input.Subject.Locality},
			Organization:       []string{input.Subject.Organization},
			OrganizationalUnit: []string{input.Subject.OrganizationUnit},
		},
		OCSPServer:            []string{s.ocspServerURL},
		NotBefore:             now,
		NotAfter:              now.Add(time.Duration(input.CADuration)),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if api.KeyType(input.KeyMetadata.KeyType) == api.RSA {
		rsaPub := signer.Public().(*rsa.PublicKey)
		derBytes, err = x509.CreateCertificate(rand.Reader, &templateCA, &templateCA, rsaPub, signer)
		if err != nil {
			level.Debug(s.logger).Log("err", err)
			return &api.CreateCAOutput{}, err
		}
	} else {
		ecdsaPub := signer.Public().(*ecdsa.PublicKey)
		derBytes, err = x509.CreateCertificate(rand.Reader, &templateCA, &templateCA, ecdsaPub, signer)
		if err != nil {
			level.Debug(s.logger).Log("err", err)
			return &api.CreateCAOutput{}, err
		}
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		level.Debug(s.logger).Log("err", err)
		return &api.CreateCAOutput{}, err
	}

	err = s.certificateRepository.InsertCA(ctx, input.CAType, cert, input.IssuanceDuration)
	if err != nil {
		level.Debug(s.logger).Log("err", err)
		return &api.CreateCAOutput{}, err
	}

	ca, err := s.certificateRepository.SelectCAByName(ctx, input.CAType, input.Subject.CommonName)
	if err != nil {
		level.Debug(s.logger).Log("err", err)
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
					level.Debug(s.logger).Log("err", err, "msg", "Could not update the status of an expired Certificate status: "+c.CAName+"-"+c.SerialNumber)
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
				level.Debug(s.logger).Log("err", err, "msg", "Could not update the status of an expired Certificate status: "+certificate.CAName+"-"+certificate.SerialNumber)
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
		level.Debug(s.logger).Log("err", err)
		return &api.SignCertificateRequestOutput{}, err
	}

	if caOutput.Status == api.StatusExpired || caOutput.Status == api.StatusRevoked {
		return &api.SignCertificateRequestOutput{}, errors.New("CA is expired or revoked")
	}

	privkey, err := s.cryptoEngine.GetPrivateKeyByID(caOutput.CAName)
	if err != nil {
		level.Debug(s.logger).Log("err", err)
		return &api.SignCertificateRequestOutput{}, err
	}

	var subject pkix.Name
	if input.SignVerbatim {
		subject = input.CertificateSigningRequest.Subject
	} else {
		subject = pkix.Name{
			CommonName: input.CommonName,
		}
	}

	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))

	now := time.Now()

	certificateTemplate := x509.Certificate{
		Signature:          input.CertificateSigningRequest.Signature,
		SignatureAlgorithm: input.CertificateSigningRequest.SignatureAlgorithm,

		PublicKeyAlgorithm: input.CertificateSigningRequest.PublicKeyAlgorithm,
		PublicKey:          input.CertificateSigningRequest.PublicKey,

		SerialNumber: sn,
		Issuer:       caOutput.Certificate.Certificate.Subject,
		Subject:      subject,
		NotBefore:    now,
		NotAfter:     now.Add(caOutput.IssuanceDuration),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, caOutput.Certificate.Certificate, input.CertificateSigningRequest.PublicKey, privkey)
	if err != nil {
		level.Debug(s.logger).Log("err", err)
		return &api.SignCertificateRequestOutput{}, &caerrors.GenericError{
			StatusCode: 400,
			Message:    err.Error(),
		}
	}

	certificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		level.Debug(s.logger).Log("err", err)
		return &api.SignCertificateRequestOutput{}, err
	}

	err = s.certificateRepository.InsertCertificate(ctx, input.CAType, input.CAName, certificate)
	if err != nil {
		level.Debug(s.logger).Log("err", err)
		return &api.SignCertificateRequestOutput{}, err
	}

	return &api.SignCertificateRequestOutput{
		Certificate:   certificate,
		CACertificate: caOutput.Certificate.Certificate,
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
