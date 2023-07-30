package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/cryptoengines"
	"github.com/lamassuiot/lamassuiot/pkg/v3/errs"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage"
	"github.com/lamassuiot/lamassuiot/pkg/v3/x509engines"
	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
)

var (
	log = logrus.WithField("subsystem", "Service")
)

type CAMiddleware func(CAService) CAService

type CAService interface {
	// GetStats() models.CAStats
	GetCryptoEngineProvider() ([]*models.CryptoEngineProvider, error)

	//returns a singnature in bytes

	CreateCA(input CreateCAInput) (*models.CACertificate, error)
	ImportCA(input ImportCAInput) (*models.CACertificate, error)
	GetCAByID(input GetCAByIDInput) (*models.CACertificate, error)
	GetCAs(input GetCAsInput) (string, error)
	UpdateCAStatus(input UpdateCAStatusInput) (*models.CACertificate, error)
	UpdateCAMetadata(input UpdateCAMetadataInput) (*models.CACertificate, error)
	DeleteCA(input DeleteCAInput) error

	SignCertificate(input SignCertificateInput) (*models.Certificate, error)
	GetCertificateBySerialNumber(input GetCertificatesBySerialNumberInput) (*models.Certificate, error)
	GetCertificates(input GetCertificatesInput) (string, error)
	GetCertificatesByCA(input GetCertificatesByCAInput) (string, error)
	GetCertificatesByExpirationDate(input GetCertificatesByExpirationDateInput) (string, error)
	UpdateCertificateStatus(input UpdateCertificateStatusInput) (*models.Certificate, error)
	UpdateCertificateMetadata(input UpdateCertificateMetadataInput) (*models.Certificate, error)
}

var lCA *logrus.Entry

var validate *validator.Validate

type Engine struct {
	Default bool
	Service cryptoengines.CryptoEngine
}

type CAServiceImpl struct {
	service               CAService
	cryptoEngines         map[string]*cryptoengines.CryptoEngine
	defaultCryptoEngine   *cryptoengines.CryptoEngine
	defaultCryptoEngineID string
	caStorage             storage.CACertificatesRepo
	certStorage           storage.CertificatesRepo
	cronInstance          *cron.Cron
	cryptoMonitorConfig   config.CryptoMonitoring
}

type CAServiceBuilder struct {
	Logger               *logrus.Entry
	CryptoEngines        map[string]*Engine
	CAStorage            storage.CACertificatesRepo
	CertificateStorage   storage.CertificatesRepo
	CryptoMonitoringConf config.CryptoMonitoring
}

func NeCAService(builder CAServiceBuilder) (CAService, error) {
	validate = validator.New()

	lCA = builder.Logger

	engines := map[string]*cryptoengines.CryptoEngine{}
	var defaultCryptoEngine *cryptoengines.CryptoEngine
	var defaultCryptoEngineID string
	for engineID, engineInstance := range builder.CryptoEngines {
		engines[engineID] = &engineInstance.Service
		if engineInstance.Default {
			defaultCryptoEngine = &engineInstance.Service
			defaultCryptoEngineID = engineID
		}
	}

	if defaultCryptoEngine == nil {
		return nil, fmt.Errorf("could not find the default cryptoengine")
	}

	svc := CAServiceImpl{
		cronInstance:          cron.New(),
		cryptoEngines:         engines,
		defaultCryptoEngine:   defaultCryptoEngine,
		defaultCryptoEngineID: defaultCryptoEngineID,
		caStorage:             builder.CAStorage,
		certStorage:           builder.CertificateStorage,
		cryptoMonitorConfig:   builder.CryptoMonitoringConf,
	}

	svc.service = &svc

	internalCAs := []models.InternalCA{
		models.CALocalRA,
	}

	for _, internalCA := range internalCAs {
		exists, _, err := svc.caStorage.SelectExists(context.Background(), string(internalCA))
		if err != nil {
			lCA.Panicf("could not initialize service: could not check if internal CA '%s' exists: %s", internalCA, err)
		}

		if !exists {
			caDur, _ := models.ParseDuration("50y")
			issuanceDur, _ := models.ParseDuration("3y")
			_, err := svc.service.CreateCA(CreateCAInput{
				CAType: models.CATypeManaged,
				KeyMetadata: models.KeyMetadata{
					Type: models.KeyType(x509.ECDSA),
					Bits: 256,
				},
				Subject: models.Subject{
					CommonName:       string(internalCA),
					Organization:     "LAMASSU",
					OrganizationUnit: "INTERNAL CA",
				},
				CAExpitration: models.Expiration{
					Type:     models.Duration,
					Duration: (*models.TimeDuration)(&caDur),
				},
				IssuanceExpiration: models.Expiration{
					Type:     models.Duration,
					Duration: (*models.TimeDuration)(&issuanceDur),
				},
			})

			if err != nil {
				lCA.Panicf("could not initialize service: could not create internal CA '%s': %s", internalCA, err)
			}
		}
	}

	cryptoMonitor := func() {
		//TODO
		criticalDelta, err := models.ParseDuration(svc.cryptoMonitorConfig.StatusMachineDeltas.CriticalExpiration)
		if err != nil {
			criticalDelta = time.Duration(time.Hour * 24 * 3)
			lCA.Warnf("could not parse StatusMachineDeltas.CriticalExpiration. Using default [%s]: %s", models.DurationToString(criticalDelta), err)
		}

		nearExpDelta, err := models.ParseDuration(svc.cryptoMonitorConfig.StatusMachineDeltas.NearExpiration)
		if err != nil {
			nearExpDelta = time.Duration(time.Hour * 24 * 7)
			lCA.Warnf("could not parse StatusMachineDeltas.NearExpiration. Using default [%s]: %s", models.DurationToString(criticalDelta), err)
		}

		if svc.cryptoMonitorConfig.AutomaticCARotation.Enabled {
			reenrollableCADelta, err := models.ParseDuration(svc.cryptoMonitorConfig.AutomaticCARotation.RenewalDelta)
			if err != nil {
				reenrollableCADelta = time.Duration(time.Hour * 24 * 7)
				lCA.Warnf("could not parse AutomaticCARotation.RenewalDelta. Using default [%s]: %s", models.DurationToString(reenrollableCADelta), err)
			}

			lCA.Infof("scheduled run: checking CA status")
			//Change with specific GetNearingExpiration
			if err != nil {
				lCA.Errorf("error while geting cas: %s", err)
				return
			}

			caScanFunc := func(ca *models.CACertificate) {
				// allowableRotTime := ca.Certificate.Certificate.NotAfter.Add(-time.Duration(ca.IssuanceDuration)).Add(-reenrollableCADelta)
				// now := time.Now()
				// if allowableRotTime.After(now) {
				// 	lCA.Tracef(
				// 		"not rotating CA %s. Now is %s. Expiration (minus IssuanceDuration and RenewalDelta) is %s. Delta is %s ",
				// 		ca.ID,
				// 		now.Format("2006-01-02 15:04:05"),
				// 		allowableRotTime.Format("2006-01-02 15:04:05"),
				// 		models.DurationToString(allowableRotTime.Sub(now)),
				// 	)
				// } else {
				// 	lCA.Infof(
				// 		"rotating CA %s. Now is %s. Expiration (minus IssuanceDuration and RenewalDelta) is %s. Delta is %s ",
				// 		ca.ID,
				// 		now.Format("2006-01-02 15:04:05"),
				// 		allowableRotTime.Format("2006-01-02 15:04:05"),
				// 		models.DurationToString(allowableRotTime.Sub(now)),
				// 	)

				// 	_, err = svc.service.RotateCA(RotateCAInput{
				// 		CAID: ca.ID,
				// 	})
				// 	if err != nil {
				// 		lCA.Errorf("something went wrong while rotating CA: %s", err)
				// 	}
				// }
			}

			svc.service.GetCAs(GetCAsInput{
				QueryParameters: nil,
				ExhaustiveRun:   true,
				ApplyFunc:       caScanFunc,
			})
		}

		now := time.Now()
		caScanFunc := func(ca *models.CACertificate) {
			if ca.ValidTo.Before(now) {
				svc.UpdateCAStatus(UpdateCAStatusInput{
					CAID:   ca.ID,
					Status: models.StatusExpired,
				})
			}
		}

		svc.service.GetCAs(GetCAsInput{
			QueryParameters: nil,
			ExhaustiveRun:   true,
			ApplyFunc:       caScanFunc,
		})

		svc.service.GetCertificatesByExpirationDate(GetCertificatesByExpirationDateInput{
			ListInput: ListInput[models.Certificate]{
				QueryParameters: nil,
				ExhaustiveRun:   true,
				ApplyFunc: func(cert *models.Certificate) {
					lCA.Debugf("updating certificate status from cert with sn '%s' to status '%s'", cert.SerialNumber, models.StatusExpired)
					svc.service.UpdateCertificateStatus(UpdateCertificateStatusInput{
						SerialNumber: cert.SerialNumber,
						NewStatus:    models.StatusExpired,
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
					lCA.Debugf("updating certificate status from cert with sn '%s' to status '%s'", cert.SerialNumber, models.StatusCriticalExpiration)
					svc.service.UpdateCertificateStatus(UpdateCertificateStatusInput{
						SerialNumber: cert.SerialNumber,
						NewStatus:    models.StatusCriticalExpiration,
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
					lCA.Debugf("updating certificate status from cert with sn '%s' to status '%s'", cert.SerialNumber, models.StatusNearingExpiration)
					svc.service.UpdateCertificateStatus(UpdateCertificateStatusInput{
						SerialNumber: cert.SerialNumber,
						NewStatus:    models.StatusNearingExpiration,
					})
				},
			},
			ExpiresAfter:  now.Add(criticalDelta).Add(time.Microsecond),
			ExpiresBefore: now.Add(nearExpDelta),
		})

	}

	cryptoMonitor()

	if builder.CryptoMonitoringConf.Enabled {
		_, err := svc.cronInstance.AddFunc(builder.CryptoMonitoringConf.Frequency, cryptoMonitor)
		if err != nil {
			lCA.Errorf("could not add scheduled run for checking certificat expiration dates")
		}

		svc.cronInstance.Start()
	}

	return &svc, nil
}

func (svc *CAServiceImpl) SetService(service CAService) {
	svc.service = service
}

func (svc *CAServiceImpl) GetCryptoEngineProvider() ([]*models.CryptoEngineProvider, error) {
	info := []*models.CryptoEngineProvider{}
	for engineID, engine := range svc.cryptoEngines {
		engineInstance := *engine
		engineInfo := engineInstance.GetEngineConfig()
		info = append(info, &models.CryptoEngineProvider{
			CryptoEngineInfo: engineInfo,
			ID:               engineID,
			Default:          engineID == svc.defaultCryptoEngineID,
		})
	}

	return info, nil
}

type SignInput struct {
	CAID               string
	Message            []byte
	MessageType        models.SigningMessageType
	SignatureAlgorithm models.SigningAlgorithm
}

type issueCAInput struct {
	KeyMetadata   models.KeyMetadata `validate:"required"`
	Subject       models.Subject     `validate:"required"`
	CAType        models.CAType      `validate:"required"`
	CAExpitration models.Expiration
}

type issueCAOutput struct {
	Certificate *x509.Certificate
}

func (svc *CAServiceImpl) issueCA(input issueCAInput) (*issueCAOutput, error) {
	var err error

	x509Engine := x509engines.NewX509Engine(svc.defaultCryptoEngine, "")

	var caCert *x509.Certificate
	expiration := time.Now()
	if input.CAExpitration.Type == models.Duration {
		expiration = expiration.Add(time.Duration(*input.CAExpitration.Duration))
	} else {
		expiration = *input.CAExpitration.Time
	}

	caCert, err = x509Engine.CreateRootCA(input.KeyMetadata, input.Subject, expiration)
	if err != nil {
		return nil, err
	}

	return &issueCAOutput{
		Certificate: caCert,
	}, nil
}

type ImportCAInput struct {
	CAType             models.CAType             `validate:"required"`
	IssuanceExpiration models.Expiration         `validate:"required"`
	CACertificate      *models.X509Certificate   `validate:"required"`
	CAChain            []*models.X509Certificate //Parent CAs. They MUST be sorted as follows. 0: Root-CA; 1: Subordinate CA from Root-CA; ...
	CARSAKey           *rsa.PrivateKey
	KeyType            models.KeyType
	CAECKey            *ecdsa.PrivateKey
}

// Returned Error Codes:
//   - ErrCAIncompatibleExpirationTimeRef
//     The Expiration time ref is incompatible with the selected variable, i.e. if the time ref is Duration the variable must be of type Duration not of type Time.
//   - ErrCAIssuanceExpiration
//     When creating a CA, the Issuance Expiration is greater than the CA Expiration.
//   - ErrCAType
//     The CA Type cannot have the value of MANAGED.
//   - ErrCAValidCertAndPrivKey
//     The CA certificate and the private key provided are not compatible.
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceImpl) ImportCA(input ImportCAInput) (*models.CACertificate, error) {
	var err error
	err = validate.Struct(input)
	if err != nil {
		return nil, errs.ErrValidateBadRequest
	}

	caCert := input.CACertificate

	if input.CAType == models.CATypeManaged {
		return nil, errs.ErrCAType
	}

	if !helpers.ValidateCAExpiration(input.IssuanceExpiration, caCert.NotAfter) {
		return nil, errs.ErrCAIssuanceExpiration
	}

	if input.CAType != models.CATypeExternal {
		if !helpers.ValidateExpirationTimeRef(input.IssuanceExpiration) {
			return nil, errs.ErrCAIncompatibleExpirationTimeRef
		}

		valid, err := helpers.ValidateCertAndPrivKey((*x509.Certificate)(caCert), input.CARSAKey, input.CAECKey)
		if err != nil {
			return nil, err
		}

		if !valid {
			return nil, errs.ErrCAValidCertAndPrivKey
		}

		engine := *svc.defaultCryptoEngine
		if input.CAType != models.CATypeExternal {
			if input.CARSAKey != nil {
				_, err = engine.ImportRSAPrivateKey(input.CARSAKey, input.CACertificate.Subject.CommonName)
			} else if input.CAECKey != nil {
				_, err = engine.ImportECDSAPrivateKey(input.CAECKey, input.CACertificate.Subject.CommonName)
			} else {
				return nil, fmt.Errorf("KeyType not supported")
			}
		}

		if err != nil {
			return nil, fmt.Errorf("could not import key: %w", err)
		}

	}

	caID := goid.NewV4UUID().String()
	ca := &models.CACertificate{
		ID:   caID,
		Type: input.CAType,
		Metadata: map[string]interface{}{
			"lamassu.io/name": caCert.Subject.CommonName,
		},
		IssuanceExpirationRef: input.IssuanceExpiration,
		CreationTS:            time.Now(),
		Certificate: models.Certificate{
			Fingerprint:         helpers.X509CertFingerprint(x509.Certificate(*input.CACertificate)),
			Certificate:         input.CACertificate,
			Status:              models.StatusActive,
			SerialNumber:        helpers.SerialNumberToString(caCert.SerialNumber),
			KeyMetadata:         helpers.KeyStrengthMetadataFromCertificate((*x509.Certificate)(caCert)),
			Subject:             helpers.PkixNameToSubject(caCert.Subject),
			ValidFrom:           caCert.NotBefore,
			ValidTo:             caCert.NotAfter,
			RevocationTimestamp: time.Time{},
			IssuerCAMetadata: models.IssuerCAMetadata{
				CAID:         caID,
				SerialNumber: helpers.SerialNumberToString(input.CACertificate.SerialNumber),
			},
		},
	}

	return svc.caStorage.Insert(context.Background(), ca)
}

type CreateCAInput struct {
	CAType             models.CAType      `validate:"required"`
	KeyMetadata        models.KeyMetadata `validate:"required"`
	Subject            models.Subject     `validate:"required"`
	IssuanceExpiration models.Expiration  `validate:"required"`
	CAExpitration      models.Expiration  `validate:"required"`
}

// Returned Error Codes:
//   - ErrCAIncompatibleExpirationTimeRef
//     The Expiration time ref is incompatible with the selected variable, i.e. if the time ref is Duration the variable must be of type Duration not of type Time.
//   - ErrCAIssuanceExpiration
//     When creating a CA, the Issuance Expiration is greater than the CA Expiration.
//   - ErrCAType
//     When creating the CA, the CA Type must have the value of MANAGED.
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceImpl) CreateCA(input CreateCAInput) (*models.CACertificate, error) {
	var err error
	err = validate.Struct(input)
	if err != nil {
		return nil, errs.ErrValidateBadRequest
	}
	if input.CAType != models.CATypeManaged {
		return nil, errs.ErrCAType
	}

	if !helpers.ValidateExpirationTimeRef(input.IssuanceExpiration) || !helpers.ValidateExpirationTimeRef(input.CAExpitration) {
		return nil, errs.ErrCAIncompatibleExpirationTimeRef
	}

	expiration := time.Now()
	if input.CAExpitration.Type == models.Duration {
		expiration = expiration.Add(time.Duration(*input.CAExpitration.Duration))
	} else {
		expiration = *input.CAExpitration.Time
	}

	if !helpers.ValidateCAExpiration(input.IssuanceExpiration, expiration) {
		return nil, errs.ErrCAIssuanceExpiration
	}

	issuedCA, err := svc.issueCA(issueCAInput{
		KeyMetadata:   input.KeyMetadata,
		Subject:       input.Subject,
		CAType:        input.CAType,
		CAExpitration: input.CAExpitration,
	})
	if err != nil {
		return nil, err
	}

	caCert := issuedCA.Certificate
	caID := goid.NewV4UUID().String()
	ca := models.CACertificate{
		ID: caID,
		Metadata: map[string]interface{}{
			"lamassu.io/name": caCert.Subject.CommonName,
		},
		IssuanceExpirationRef: input.IssuanceExpiration,
		Type:                  input.CAType,
		CreationTS:            time.Now(),
		Certificate: models.Certificate{
			Fingerprint:  helpers.X509CertFingerprint(*caCert),
			Certificate:  (*models.X509Certificate)(caCert),
			Status:       models.StatusActive,
			SerialNumber: helpers.SerialNumberToString(caCert.SerialNumber),
			KeyMetadata: models.KeyStrengthMetadata{
				Type:     input.KeyMetadata.Type,
				Bits:     input.KeyMetadata.Bits,
				Strength: models.KeyStrengthHigh,
			},
			Subject:             input.Subject,
			ValidFrom:           caCert.NotBefore,
			ValidTo:             caCert.NotAfter,
			RevocationTimestamp: time.Time{},
			IssuerCAMetadata: models.IssuerCAMetadata{
				SerialNumber: helpers.SerialNumberToString(caCert.SerialNumber),
				CAID:         caID,
			},
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
	CAID string `validate:"required"`
}

type GetCAByIDInput struct {
	CAID string `validate:"required"`
}

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceImpl) GetCAByID(input GetCAByIDInput) (*models.CACertificate, error) {
	err := validate.Struct(input)
	if err != nil {
		return nil, errs.ErrValidateBadRequest
	}

	exists, ca, err := svc.caStorage.SelectExists(context.Background(), input.CAID)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, errs.ErrCANotFound
	}

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
	CAID   string                   `validate:"required"`
	Status models.CertificateStatus `validate:"required"`
}

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
//   - ErrCAAlreadyRevoked
//     CA already revoked
func (svc *CAServiceImpl) UpdateCAStatus(input UpdateCAStatusInput) (*models.CACertificate, error) {
	err := validate.Struct(input)
	if err != nil {
		return nil, errs.ErrValidateBadRequest
	}

	exists, ca, err := svc.caStorage.SelectExists(context.Background(), input.CAID)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, errs.ErrCANotFound
	}

	if ca.Status == models.StatusRevoked {
		return nil, errs.ErrCAAlreadyRevoked
	}
	ca.Status = input.Status

	ca, err = svc.caStorage.Update(context.Background(), ca)
	if err != nil {
		return nil, err
	}

	if input.Status == models.StatusRevoked {
		revokeCertFunc := func(c *models.Certificate) {
			_, err := svc.UpdateCertificateStatus(UpdateCertificateStatusInput{
				SerialNumber: c.SerialNumber,
				NewStatus:    models.StatusRevoked,
			})
			if err != nil {
				lCA.Errorf("could not revoke certificate %s issued by CA %s", c.SerialNumber, c.IssuerCAMetadata.CAID)
			}
		}

		_, err = svc.certStorage.SelectByCA(context.Background(), ca.IssuerCAMetadata.CAID, true, revokeCertFunc, &resources.QueryParameters{}, map[string]interface{}{})
		if err != nil {
			return nil, err
		}
	}

	return ca, err
}

type UpdateCAMetadataInput struct {
	CAID     string                 `validate:"required"`
	Metadata map[string]interface{} `validate:"required"`
}

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceImpl) UpdateCAMetadata(input UpdateCAMetadataInput) (*models.CACertificate, error) {
	err := validate.Struct(input)
	if err != nil {
		return nil, errs.ErrValidateBadRequest
	}
	exists, ca, err := svc.caStorage.SelectExists(context.Background(), input.CAID)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, errs.ErrCANotFound
	}

	ca.Metadata = input.Metadata

	return svc.caStorage.Update(context.Background(), ca)
}

type DeleteCAInput struct {
	CAID string `validate:"required"`
}

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
//   - ErrCAStatus
//     Cannot delete a CA that is not expired or revoked.
func (svc *CAServiceImpl) DeleteCA(input DeleteCAInput) error {
	err := validate.Struct(input)
	if err != nil {
		return errs.ErrValidateBadRequest
	}

	exists, ca, err := svc.caStorage.SelectExists(context.Background(), input.CAID)
	if err != nil {
		return err
	}

	if !exists {
		return errs.ErrCANotFound
	}

	if ca.Status != models.StatusExpired && ca.Status != models.StatusRevoked {
		return errs.ErrCAStatus
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

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
//   - ErrCAStatus
//     CA is not active
func (svc *CAServiceImpl) SignCertificate(input SignCertificateInput) (*models.Certificate, error) {
	err := validate.Struct(input)
	if err != nil {
		return nil, errs.ErrCANotFound
	}

	exists, ca, err := svc.caStorage.SelectExists(context.Background(), input.CAID)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, errs.ErrCANotFound
	}

	if ca.Status != models.StatusActive {
		return nil, errs.ErrCAStatus
	}

	x509Engine := x509engines.NewX509Engine(svc.defaultCryptoEngine, "")

	caCert := (*x509.Certificate)(ca.Certificate.Certificate)
	csr := (*x509.CertificateRequest)(input.CertRequest)

	if !input.SignVerbatim {
		csr.Subject = pkix.Name{
			CommonName:         input.Subject.CommonName,
			Country:            []string{input.Subject.Country},
			Province:           []string{input.Subject.State},
			Locality:           []string{input.Subject.Locality},
			Organization:       []string{input.Subject.Organization},
			OrganizationalUnit: []string{input.Subject.OrganizationUnit},
		}
	}

	expiration := time.Now()
	if ca.IssuanceExpirationRef.Type == models.Duration {
		expiration = expiration.Add(time.Duration(*ca.IssuanceExpirationRef.Duration))
	} else {
		expiration = *ca.IssuanceExpirationRef.Time
	}

	x509Cert, err := x509Engine.SignCertificateRequest(caCert, csr, expiration)
	if err != nil {
		return nil, err
	}

	cert := models.Certificate{
		Certificate: (*models.X509Certificate)(x509Cert),
		Fingerprint: helpers.X509CertFingerprint(*x509Cert),
		IssuerCAMetadata: models.IssuerCAMetadata{
			SerialNumber: helpers.SerialNumberToString(caCert.SerialNumber),
			CAID:         ca.ID,
		},
		Status:              models.StatusActive,
		KeyMetadata:         helpers.KeyStrengthMetadataFromCertificate(x509Cert),
		Subject:             helpers.PkixNameToSubject(x509Cert.Subject),
		SerialNumber:        helpers.SerialNumberToString(x509Cert.SerialNumber),
		ValidFrom:           x509Cert.NotBefore,
		ValidTo:             x509Cert.NotAfter,
		RevocationTimestamp: time.Time{},
	}

	return svc.certStorage.Insert(context.Background(), &cert)
}

type GetCertificatesBySerialNumberInput struct {
	SerialNumber string `validate:"required"`
}

// Returned Error Codes:
//   - ErrCertificateNotFound
//     The specified Certificate can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceImpl) GetCertificateBySerialNumber(input GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	err := validate.Struct(input)
	if err != nil {
		return nil, errs.ErrValidateBadRequest
	}

	exists, cert, err := svc.certStorage.SelectExists(context.Background(), input.SerialNumber)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, errs.ErrCertificateNotFound
	}

	return cert, nil
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

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceImpl) GetCertificatesByCA(input GetCertificatesByCAInput) (string, error) {
	err := validate.Struct(input)
	if err != nil {
		return "", errs.ErrValidateBadRequest
	}

	exists, _, err := svc.caStorage.SelectExists(context.Background(), input.CAID)
	if err != nil {
		return "", err
	}

	if !exists {
		return "", errs.ErrCANotFound
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
	NewStatus    models.CertificateStatus `validate:"required"`
	// RevocationReason models.RevocationReasonRFC5280
}

// Returned Error Codes:
//   - ErrCertificateNotFound
//     The specified Certificate can not be found in the Database
//   - ErrCertificateStatusTransitionNotAllowed
//     The specified status is not valid for this certficate due to its initial status
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceImpl) UpdateCertificateStatus(input UpdateCertificateStatusInput) (*models.Certificate, error) {
	err := validate.Struct(input)
	if err != nil {
		return nil, errs.ErrValidateBadRequest
	}

	exsits, cert, err := svc.certStorage.SelectExists(context.Background(), input.SerialNumber)
	if err != nil {
		return nil, err
	}

	if !exsits {
		return nil, errs.ErrCertificateNotFound
	}

	if cert.Status == input.NewStatus {
		return cert, nil
	} else if cert.Status == models.StatusExpired || cert.Status == models.StatusRevoked {
		return nil, errs.ErrCertificateStatusTransitionNotAllowed
	} else if cert.Status == models.StatusNearingExpiration && input.NewStatus == models.StatusActive {
		return nil, errs.ErrCertificateStatusTransitionNotAllowed
	}

	cert.Status = input.NewStatus

	// if input.NewStatus == models.StatusRevoked {
	// 	cert.RevocationReason = input.RevocationReason
	// }

	return svc.certStorage.Update(context.Background(), cert)
}

type UpdateCertificateMetadataInput struct {
	SerialNumber string                 `validate:"required"`
	Metadata     map[string]interface{} `validate:"required"`
}

// Returned Error Codes:
//   - ErrCertificateNotFound
//     The specified Certificate can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceImpl) UpdateCertificateMetadata(input UpdateCertificateMetadataInput) (*models.Certificate, error) {
	err := validate.Struct(input)
	if err != nil {
		return nil, errs.ErrValidateBadRequest
	}

	exists, cert, err := svc.certStorage.SelectExists(context.Background(), input.SerialNumber)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, errs.ErrCertificateNotFound
	}

	cert.Metadata = input.Metadata

	return svc.certStorage.Update(context.Background(), cert)
}
