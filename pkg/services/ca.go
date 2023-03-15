package services

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/internal/ca/cryptoengines"
	"github.com/lamassuiot/lamassuiot/internal/ca/x509engine"
	"github.com/lamassuiot/lamassuiot/pkg/config"
	"github.com/lamassuiot/lamassuiot/pkg/helppers"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/resources"
	"github.com/lamassuiot/lamassuiot/pkg/storage"
	"github.com/robfig/cron/v3"
	log "github.com/sirupsen/logrus"
)

type CAMiddleware func(CAService) CAService

type CAService interface {
	GetCryptoEngineProviders() []models.EngineProvider

	CreateCA(input CreateCAInput) (*models.CACertificate, error)
	GetCAByID(input GetCAByIDInput) (*models.CACertificate, error)
	GetCAs(input GetCAsInput) (string, error)
	UpdateCAStatus(input UpdateCAStatusInput) (*models.CACertificate, error)
	RotateCA(input RotateCAInput) (*models.CACertificate, error)
	DeleteCA(input DeleteCAInput) error

	SignCertificate(input SignCertificateInput) (*models.Certificate, error)
	GetCertificateBySerialNumber(input GetCertificatesBySerialNumberInput) (*models.Certificate, error)
	GetCertificates(input GetCertificatesInput) (string, error)
	GetCertificatesByCA(input GetCertificatesByCAInput) (string, error)
	GetCertificatesByExpirationDate(input GetCertificatesByExpirationDateInput) (string, error)
	UpdateCertificateStatus(input UpdateCertificateStatusInput) (*models.Certificate, error)
}

var (
	ErrCANotFound                 error = errors.New("CA not found")
	ErrCertificateNotFound        error = errors.New("certificate not found")
	ErrEngineNotFound             error = errors.New("engine not found")
	ErrAlreadyRevoked             error = errors.New("already revoked")
	ErrSignRequestNotInPEMFormat  error = errors.New("csr is not in PEM format")
	ErrSignRequestNotInB64        error = errors.New("csr is not encoded in base64")
	ErrStatusTransitionNotAllowed error = errors.New("status transition not allowed")
)

type EngineServiceMap struct {
	Name         string
	Metadata     map[string]interface{}
	CryptoEngine cryptoengines.CryptoEngine
}

var validate *validator.Validate

type CAServiceImpl struct {
	service                 CAService
	cryptoEngineServicesMap map[string]EngineServiceMap
	caStorage               storage.CACertificatesRepo
	certStorage             storage.CertificatesRepo
	cronInstance            *cron.Cron
	crtyptoMonitorConfig    config.CryptoMonitoring
}

type CAServiceBuilder struct {
	CryptoEngines        map[string]EngineServiceMap
	CAStorage            storage.CACertificatesRepo
	CertificateStorage   storage.CertificatesRepo
	CryptoMonitoringConf config.CryptoMonitoring
}

func NeCAService(builder CAServiceBuilder) CAService {
	validate = validator.New()

	svc := CAServiceImpl{
		cronInstance:            cron.New(),
		cryptoEngineServicesMap: builder.CryptoEngines,
		caStorage:               builder.CAStorage,
		certStorage:             builder.CertificateStorage,
		crtyptoMonitorConfig:    builder.CryptoMonitoringConf,
	}

	svc.service = &svc

	cryptoMonitor := func() {
		//TODO
		criticalDelta, err := models.ParseDuration(svc.crtyptoMonitorConfig.StatusMachineDeltas.CriticalExpiration)
		if err != nil {
			criticalDelta = time.Duration(time.Hour * 24 * 3)
			log.Warnf("could not parse StatusMachineDeltas.CriticalExpiration. Using default [%s]: %s", models.DurationToString(criticalDelta), err)
		}

		nerarExpDelta, err := models.ParseDuration(svc.crtyptoMonitorConfig.StatusMachineDeltas.NearExpiration)
		if err != nil {
			nerarExpDelta = time.Duration(time.Hour * 24 * 7)
			log.Warnf("could not parse StatusMachineDeltas.NearExpiration. Using default [%s]: %s", models.DurationToString(criticalDelta), err)
		}

		if svc.crtyptoMonitorConfig.AutomaticCARotation.Enabled {
			reenrollableCADelta, err := models.ParseDuration(svc.crtyptoMonitorConfig.AutomaticCARotation.RenewalDelta)
			if err != nil {
				reenrollableCADelta = time.Duration(time.Hour * 24 * 7)
				log.Warnf("could not parse AutomaticCARotation.RenewalDelta. Using default [%s]: %s", models.DurationToString(reenrollableCADelta), err)
			}

			log.Infof("%s - scheduled run: checking CA status", time.Now().Format("2006-01-02 15:04:05"))
			//Change with specific GetNearingExpiration
			if err != nil {
				log.Errorf("error while geting cas: %s", err)
				return
			}

			caScanFunc := func(ca *models.CACertificate) {
				allowableRotTime := ca.Certificate.Certificate.NotAfter.Add(-time.Duration(ca.IssuanceDuration)).Add(-reenrollableCADelta)
				now := time.Now()
				if allowableRotTime.After(now) {
					log.Tracef(
						"not rotating CA %s. Now is %s. Expiration (minus IssuanceDuration and RenewalDelta) is %s. Delta is %s ",
						ca.ID,
						now.Format("2006-01-02 15:04:05"),
						allowableRotTime.Format("2006-01-02 15:04:05"),
						models.DurationToString(allowableRotTime.Sub(now)),
					)
				} else {
					log.Infof(
						"rotating CA %s. Now is %s. Expiration (minus IssuanceDuration and RenewalDelta) is %s. Delta is %s ",
						ca.ID,
						now.Format("2006-01-02 15:04:05"),
						allowableRotTime.Format("2006-01-02 15:04:05"),
						models.DurationToString(allowableRotTime.Sub(now)),
					)

					_, err = svc.service.RotateCA(RotateCAInput{
						ID: ca.ID,
					})
					if err != nil {
						log.Errorf("something went wrong while rotating CA: %s", err)
					}
				}
			}

			svc.service.GetCAs(GetCAsInput{
				QueryParameters: nil,
				ExhaustiveRun:   true,
				ApplyFunc:       caScanFunc,
			})
		}

		now := time.Now()
		svc.service.GetCertificatesByExpirationDate(GetCertificatesByExpirationDateInput{
			ListInput: ListInput[models.Certificate]{
				QueryParameters: nil,
				ExhaustiveRun:   true,
				ApplyFunc: func(cert *models.Certificate) {
					svc.service.UpdateCertificateStatus(UpdateCertificateStatusInput{
						SerialNumber: cert.SerialNumber,
						Status:       models.StatusExpired,
					})
				},
			},
			ExpiresAfter:  time.Time{},
			ExpiresBefore: now,
		})
		svc.service.GetCertificatesByExpirationDate(GetCertificatesByExpirationDateInput{
			ListInput: ListInput[models.Certificate]{
				QueryParameters: nil,
				ExhaustiveRun:   true,
				ApplyFunc: func(cert *models.Certificate) {
					svc.service.UpdateCertificateStatus(UpdateCertificateStatusInput{
						SerialNumber: cert.SerialNumber,
						Status:       models.StatusCriticalExpiration,
					})
				},
			},
			ExpiresAfter:  now,
			ExpiresBefore: now.Add(criticalDelta),
		})
		svc.service.GetCertificatesByExpirationDate(GetCertificatesByExpirationDateInput{
			ListInput: ListInput[models.Certificate]{
				QueryParameters: nil,
				ExhaustiveRun:   true,
				ApplyFunc: func(cert *models.Certificate) {
					svc.service.UpdateCertificateStatus(UpdateCertificateStatusInput{
						SerialNumber: cert.SerialNumber,
						Status:       models.StatusNearingExpiration,
					})
				},
			},
			ExpiresAfter:  now.Add(criticalDelta).Add(time.Microsecond),
			ExpiresBefore: now.Add(nerarExpDelta),
		})

	}

	cryptoMonitor()

	if builder.CryptoMonitoringConf.Enabled {
		_, err := svc.cronInstance.AddFunc(builder.CryptoMonitoringConf.Frequency, cryptoMonitor)
		if err != nil {
			log.Errorf("could not add scheduled run for checking certificat expiration dates")
		}

		svc.cronInstance.Start()
	}

	return &svc
}

func (svc *CAServiceImpl) SetService(service CAService) {
	svc.service = service
}

func (svc *CAServiceImpl) GetCryptoEngineProviders() []models.EngineProvider {
	enginesInfo := []models.EngineProvider{}
	for engineID, engine := range svc.cryptoEngineServicesMap {
		enginesInfo = append(enginesInfo, models.EngineProvider{
			ID:                   engineID,
			Name:                 engine.Name,
			Metadata:             engine.Metadata,
			CryptoEngineProvider: engine.CryptoEngine.GetEngineConfig(),
		})
	}

	return enginesInfo
}

type issueCAInput struct {
	IssuerCAID  string
	EngineID    string             `validate:"required"`
	KeyMetadata models.KeyMetadata `validate:"required"`
	Subject     models.Subject     `validate:"required"`
	CADuration  time.Duration      `validate:"required"`
	CAType      string             `validate:"required"`
}

type issueCAOutput struct {
	CertificateLevel int
	Certificate      *x509.Certificate
	IssuerCAMetadata models.IssuerCAMetadata
}

func (svc *CAServiceImpl) issueCA(input issueCAInput) (*issueCAOutput, error) {
	var err error

	engine := svc.cryptoEngineServicesMap[input.EngineID].CryptoEngine
	if engine == nil {
		return nil, ErrEngineNotFound
	}

	x509Engine := x509engine.NewX509Engine(engine, "")

	var certificateLevel = 0
	var caMetadata models.IssuerCAMetadata
	var caCert *x509.Certificate

	if input.IssuerCAID != "" {
		issuerCA, err := svc.service.GetCAByID(GetCAByIDInput{
			ID: input.IssuerCAID,
		})
		if err != nil {
			return nil, ErrCANotFound
		}

		certificateLevel = issuerCA.Level + 1

		t0 := time.Now().Add(time.Hour).Add(time.Duration(input.CADuration))
		t1 := issuerCA.Certificate.Certificate.NotAfter
		if t0.After(t1) {
			return nil, fmt.Errorf("can't issue a certificate that has a longer lifespan than the remaining lifespan of its CA parent")
		}

		if time.Now().After(issuerCA.Certificate.Certificate.NotAfter) {
			return nil, fmt.Errorf("can't issue a certificate from an expired CA")
		}

		if input.CAType != issuerCA.Metadata.Type {
			return nil, fmt.Errorf("can't issue a certificate with different type than its CA parent")
		}

		parentEngine := svc.cryptoEngineServicesMap[issuerCA.Metadata.EngineProviderID].CryptoEngine
		if engine == nil {
			return nil, fmt.Errorf("issuer engine %s does not exist. Missing engine in config file?", issuerCA.Metadata.EngineProviderID)
		}

		parentCertificate := (*x509.Certificate)(issuerCA.Certificate.Certificate)
		parentSigner, err := x509engine.NewX509Engine(parentEngine, "").GetCACryptoSigner(parentCertificate)
		if err != nil {
			return nil, fmt.Errorf("issuer signer (private key abstraction) %s does not exist. Corrupted engine?", issuerCA.Metadata.EngineProviderID)
		}

		caMetadata = models.IssuerCAMetadata{
			ID:               issuerCA.ID,
			EngineProviderID: issuerCA.Metadata.EngineProviderID,
			SerialNumber:     helppers.SerialNumberToString(parentCertificate.SerialNumber),
		}

		caCert, err = x509Engine.CreateSubordinateCA(parentCertificate, parentSigner, input.KeyMetadata, input.Subject, input.CADuration)
		if err != nil {
			return nil, err
		}

	} else {
		caCert, err = x509Engine.CreateRootCA(input.KeyMetadata, input.Subject, input.CADuration)
		if err != nil {
			return nil, err
		}

		caMetadata = models.IssuerCAMetadata{
			EngineProviderID: input.EngineID,
			ID:               goid.NewV4UUID().String(),
			SerialNumber:     helppers.SerialNumberToString(caCert.SerialNumber),
		}
	}

	return &issueCAOutput{
		CertificateLevel: certificateLevel,
		Certificate:      caCert,
		IssuerCAMetadata: caMetadata,
	}, nil
}

type CreateCAInput struct {
	IssuerCAID       string
	EngineID         string             `validate:"required"`
	CAType           string             `validate:"required"`
	KeyMetadata      models.KeyMetadata `validate:"required"`
	Subject          models.Subject     `validate:"required"`
	IssuanceDuration time.Duration      `validate:"required"`
	CADuration       time.Duration      `validate:"required"`
}

func (svc *CAServiceImpl) CreateCA(input CreateCAInput) (*models.CACertificate, error) {
	var err error
	err = validate.Struct(input)
	if err != nil {
		return nil, err
	}

	issuedCA, err := svc.issueCA(issueCAInput{
		EngineID:    input.EngineID,
		IssuerCAID:  input.IssuerCAID,
		KeyMetadata: input.KeyMetadata,
		Subject:     input.Subject,
		CADuration:  input.CADuration,
		CAType:      input.CAType,
	})
	if err != nil {
		return nil, err
	}

	caCert := issuedCA.Certificate

	caID := ""
	if issuedCA.CertificateLevel == 0 {
		caID = issuedCA.IssuerCAMetadata.ID
	} else {
		caID = goid.NewV4UUID().String()
	}

	ca := models.CACertificate{
		ID:               caID,
		Version:          0,
		IssuanceDuration: models.TimeDuration(input.IssuanceDuration),
		Metadata: models.CAMetadata{
			EngineProviderID: input.EngineID,
			Name:             input.Subject.CommonName,
			Type:             input.CAType,
		},
		VersionHistory: map[int]string{
			0: helppers.SerialNumberToString(caCert.SerialNumber),
		},
		CreationTS: caCert.NotBefore,
		Certificate: models.Certificate{
			Level:        issuedCA.CertificateLevel,
			Fingerprint:  helppers.X509CertFingerprint(*caCert),
			Certificate:  (*models.X509Certificate)(caCert),
			Status:       models.StatusActive,
			SerialNumber: helppers.SerialNumberToString(caCert.SerialNumber),
			KeyMetadata: models.KeyStrengthMetadata{
				Type:     input.KeyMetadata.Type,
				Bits:     input.KeyMetadata.Bits,
				Strength: models.KeyStrengthHigh,
			},
			Subject:             input.Subject,
			ValidFrom:           caCert.NotBefore,
			ValidTo:             caCert.NotAfter,
			RevocationTimestamp: time.Time{},
			RevocationReason:    "",
			IssuerCAMetadata:    issuedCA.IssuerCAMetadata,
		},
	}

	//Store a copy of the certificate, otherwise when rotated, the cert is lost
	_, err = svc.certStorage.Insert(context.Background(), &ca.Certificate)
	if err != nil {
		return nil, err
	}

	return svc.caStorage.Insert(context.Background(), &ca)
}

type RotateCAInput struct {
	ID string `validate:"required"`
}

func (svc *CAServiceImpl) RotateCA(input RotateCAInput) (*models.CACertificate, error) {
	err := validate.Struct(input)
	if err != nil {
		return nil, err
	}

	ca, err := svc.caStorage.Select(context.Background(), input.ID)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	if now.After(ca.Certificate.Certificate.NotAfter) {
		if !svc.crtyptoMonitorConfig.AutomaticCARotation.Enabled {
			return nil, fmt.Errorf("can't rotate expired CA. Change your configuration if necessary to enable rotating expired CAs")
		}

		log.Warn("rotating an expired CA")
	}

	issuedCA, err := svc.issueCA(issueCAInput{
		EngineID: ca.Metadata.EngineProviderID,
		KeyMetadata: models.KeyMetadata{
			Type: ca.KeyMetadata.Type,
			Bits: ca.KeyMetadata.Bits,
		},
		Subject:    ca.Subject,
		CADuration: ca.Certificate.Certificate.NotAfter.Sub(ca.Certificate.Certificate.NotBefore),
		IssuerCAID: ca.IssuerCAMetadata.ID,
		CAType:     ca.Metadata.Type,
	})
	if err != nil {
		return nil, err
	}

	newCACert := issuedCA.Certificate

	ca.Version += 1
	ca.VersionHistory[ca.Version] = helppers.SerialNumberToString(newCACert.SerialNumber)
	ca.Certificate = models.Certificate{
		Level:        issuedCA.CertificateLevel,
		Certificate:  (*models.X509Certificate)(newCACert),
		Status:       models.StatusActive,
		Fingerprint:  helppers.X509CertFingerprint(*newCACert),
		SerialNumber: helppers.SerialNumberToString(newCACert.SerialNumber),
		KeyMetadata: models.KeyStrengthMetadata{
			Type:     ca.KeyMetadata.Type,
			Bits:     ca.KeyMetadata.Bits,
			Strength: models.KeyStrengthHigh,
		},
		Subject:             ca.Subject,
		ValidFrom:           newCACert.NotBefore,
		ValidTo:             newCACert.NotAfter,
		RevocationTimestamp: time.Time{},
		RevocationReason:    "",
		IssuerCAMetadata:    issuedCA.IssuerCAMetadata,
	}

	//Store a copy of the certificate, otherwise when rotated, the cert is lost
	_, err = svc.certStorage.Insert(context.Background(), &ca.Certificate)
	if err != nil {
		return nil, err
	}

	return svc.caStorage.Update(context.Background(), ca)
}

type GetCAByIDInput struct {
	ID string `validate:"required"`
}

func (svc *CAServiceImpl) GetCAByID(input GetCAByIDInput) (*models.CACertificate, error) {
	err := validate.Struct(input)
	if err != nil {
		return nil, err
	}

	ca, err := svc.caStorage.Select(context.Background(), input.ID)
	return ca, err
}

type GetCAsInput struct {
	QueryParameters *resources.QueryParameters

	ExhaustiveRun bool //wether to iter all elems
	ApplyFunc     func(cert *models.CACertificate)
}

func (svc *CAServiceImpl) GetCAs(input GetCAsInput) (string, error) {
	nextBookmark, err := svc.caStorage.SelectAll(context.Background(), input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, nil)
	if err != nil {
		return "", err
	}

	return nextBookmark, err
}

type UpdateCAStatusInput struct {
	ID     string                   `validate:"required"`
	Status models.CertificateStatus `validate:"required"`
}

func (svc *CAServiceImpl) UpdateCAStatus(input UpdateCAStatusInput) (*models.CACertificate, error) {
	err := validate.Struct(input)
	if err != nil {
		return nil, err
	}

	ca, err := svc.caStorage.Select(context.Background(), input.ID)
	if err != nil {
		return nil, err
	}

	ca.Status = input.Status

	ca, err = svc.caStorage.Update(context.Background(), ca)
	if err != nil {
		return nil, err
	}

	return ca, err
}

type DeleteCAInput struct {
	ID string `validate:"required"`
}

func (svc *CAServiceImpl) DeleteCA(input DeleteCAInput) error {
	err := validate.Struct(input)
	if err != nil {
		return err
	}

	ca, err := svc.caStorage.Select(context.Background(), input.ID)
	if err != nil {
		return err
	}

	if ca.Status != models.StatusExpired && ca.Status != models.StatusRevoked {
		return fmt.Errorf("cannot delete a CA that is not expired or revoked")
	}

	//TODO missing implementation
	return fmt.Errorf("TODO missing implementation")
}

type SignCertificateInput struct {
	CAID         string                         `validate:"required"`
	CertRequest  *models.X509CertificateRequest `validate:"required"`
	Subject      models.Subject
	SignVerbatim bool
}

func (svc *CAServiceImpl) SignCertificate(input SignCertificateInput) (*models.Certificate, error) {
	err := validate.Struct(input)
	if err != nil {
		return nil, err
	}

	ca, err := svc.service.GetCAByID(GetCAByIDInput{
		ID: input.CAID,
	})
	if err != nil {
		return nil, err
	}

	if ca.Status != models.StatusActive {
		return nil, fmt.Errorf("CA is not active")
	}

	engine := svc.cryptoEngineServicesMap[ca.Metadata.EngineProviderID].CryptoEngine
	if engine == nil {
		return nil, fmt.Errorf("engine does not exist")
	}

	x509Engine := x509engine.NewX509Engine(engine, "")

	caCert := (*x509.Certificate)(ca.Certificate.Certificate)
	x509Cert, err := x509Engine.SignCertificateRequest(caCert, (*x509.CertificateRequest)(input.CertRequest), time.Duration(ca.IssuanceDuration), input.SignVerbatim, input.Subject)
	if err != nil {
		return nil, err
	}

	cert := models.Certificate{
		Certificate: (*models.X509Certificate)(x509Cert),
		Level:       ca.Level + 1,
		Fingerprint: helppers.X509CertFingerprint(*x509Cert),
		IssuerCAMetadata: models.IssuerCAMetadata{
			EngineProviderID: ca.Metadata.EngineProviderID,
			SerialNumber:     helppers.SerialNumberToString(caCert.SerialNumber),
			ID:               ca.ID,
		},
		Status:              models.StatusActive,
		KeyMetadata:         helppers.KeyStrengthMetadataFromCertificate(x509Cert),
		Subject:             helppers.PkixNameToSubject(x509Cert.Subject),
		SerialNumber:        helppers.SerialNumberToString(x509Cert.SerialNumber),
		ValidFrom:           x509Cert.NotBefore,
		ValidTo:             x509Cert.NotAfter,
		RevocationTimestamp: time.Time{},
		RevocationReason:    "",
	}

	return svc.certStorage.Insert(context.Background(), &cert)
}

type GetCertificatesBySerialNumberInput struct {
	SerialNumber string `validate:"required"`
}

func (svc *CAServiceImpl) GetCertificateBySerialNumber(input GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	err := validate.Struct(input)
	if err != nil {
		return nil, err
	}

	return svc.certStorage.Select(context.Background(), input.SerialNumber)
}

type GetCertificatesInput struct {
	ListInput[models.Certificate]
}

func (svc *CAServiceImpl) GetCertificates(input GetCertificatesInput) (string, error) {
	return svc.certStorage.SelectAll(context.Background(), input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, nil)
}

type GetCertificatesByCAInput struct {
	CAID string `validate:"required"`
	ListInput[models.Certificate]
}

func (svc *CAServiceImpl) GetCertificatesByCA(input GetCertificatesByCAInput) (string, error) {
	err := validate.Struct(input)
	if err != nil {
		return "", err
	}

	return svc.certStorage.SelectByCA(context.Background(), input.CAID, input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, nil)
}

type GetCertificatesByExpirationDateInput struct {
	ExpiresAfter  time.Time
	ExpiresBefore time.Time
	ListInput[models.Certificate]
}

func (svc *CAServiceImpl) GetCertificatesByExpirationDate(input GetCertificatesByExpirationDateInput) (string, error) {
	return svc.certStorage.SelectByExpirationDate(context.Background(), input.ExpiresBefore, input.ExpiresAfter, input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, map[string]interface{}{})
}

type UpdateCertificateStatusInput struct {
	SerialNumber string                   `validate:"required"`
	Status       models.CertificateStatus `validate:"required"`
}

func (svc *CAServiceImpl) UpdateCertificateStatus(input UpdateCertificateStatusInput) (*models.Certificate, error) {
	err := validate.Struct(input)
	if err != nil {
		return nil, err
	}

	cert, err := svc.certStorage.Select(context.Background(), input.SerialNumber)
	if err != nil {
		return nil, err
	}

	if cert.Status == input.Status {
		return cert, nil
	} else if cert.Status == models.StatusExpired || cert.Status == models.StatusRevoked {
		return nil, ErrStatusTransitionNotAllowed
	} else if cert.Status == models.StatusNearingExpiration && input.Status == models.StatusActive {
		return nil, ErrStatusTransitionNotAllowed
	}

	cert.Status = input.Status

	return svc.certStorage.Update(context.Background(), cert)
}
