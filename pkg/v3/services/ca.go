package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/cryptoengines"
	"github.com/lamassuiot/lamassuiot/pkg/v3/errs"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage"
	"github.com/robfig/cron/v3"
	log "github.com/sirupsen/logrus"
)

type CAMiddleware func(CAService) CAService

type CAService interface {
	// GetStats() models.CAStats
	GetCryptoEngineProvider() (*models.EngineProvider, error)

	//returns a singnature in bytes
	Sign(input SignInput) ([]byte, error)
	VerifySignature(input VerifySignatureInput) (bool, error)

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

var (
	ErrCANotFound                 error = errors.New("CA not found")
	ErrCertificateNotFound        error = errors.New("certificate not found")
	ErrEngineNotFound             error = errors.New("engine not found")
	ErrAlreadyRevoked             error = errors.New("already revoked")
	ErrSignRequestNotInPEMFormat  error = errors.New("csr is not in PEM format")
	ErrSignRequestNotInB64        error = errors.New("csr is not encoded in base64")
	ErrStatusTransitionNotAllowed error = errors.New("status transition not allowed")
)

var validate *validator.Validate

type CAServiceImpl struct {
	service             CAService
	cryptoEngine        cryptoengines.CryptoEngine
	caStorage           storage.CACertificatesRepo
	certStorage         storage.CertificatesRepo
	cronInstance        *cron.Cron
	cryptoMonitorConfig config.CryptoMonitoring
}

type CAServiceBuilder struct {
	CryptoEngine         cryptoengines.CryptoEngine
	CAStorage            storage.CACertificatesRepo
	CertificateStorage   storage.CertificatesRepo
	CryptoMonitoringConf config.CryptoMonitoring
}

func NeCAService(builder CAServiceBuilder) CAService {
	validate = validator.New()

	svc := CAServiceImpl{
		cronInstance:        cron.New(),
		cryptoEngine:        builder.CryptoEngine,
		caStorage:           builder.CAStorage,
		certStorage:         builder.CertificateStorage,
		cryptoMonitorConfig: builder.CryptoMonitoringConf,
	}

	svc.service = &svc

	internalCAs := []models.InternalCA{
		models.CALocalRA,
	}

	for _, internalCA := range internalCAs {
		exists, err := svc.caStorage.Exists(context.Background(), string(internalCA))
		if err != nil {
			log.Panicf("could not initialize service: could not check if internal CA '%s' exists: %s", internalCA, err)
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
				log.Panicf("could not initialize service: could not create internal CA '%s': %s", internalCA, err)
			}
		}
	}

	cryptoMonitor := func() {
		//TODO
		criticalDelta, err := models.ParseDuration(svc.cryptoMonitorConfig.StatusMachineDeltas.CriticalExpiration)
		if err != nil {
			criticalDelta = time.Duration(time.Hour * 24 * 3)
			log.Warnf("could not parse StatusMachineDeltas.CriticalExpiration. Using default [%s]: %s", models.DurationToString(criticalDelta), err)
		}

		nearExpDelta, err := models.ParseDuration(svc.cryptoMonitorConfig.StatusMachineDeltas.NearExpiration)
		if err != nil {
			nearExpDelta = time.Duration(time.Hour * 24 * 7)
			log.Warnf("could not parse StatusMachineDeltas.NearExpiration. Using default [%s]: %s", models.DurationToString(criticalDelta), err)
		}

		if svc.cryptoMonitorConfig.AutomaticCARotation.Enabled {
			reenrollableCADelta, err := models.ParseDuration(svc.cryptoMonitorConfig.AutomaticCARotation.RenewalDelta)
			if err != nil {
				reenrollableCADelta = time.Duration(time.Hour * 24 * 7)
				log.Warnf("could not parse AutomaticCARotation.RenewalDelta. Using default [%s]: %s", models.DurationToString(reenrollableCADelta), err)
			}

			log.Infof("scheduled run: checking CA status")
			//Change with specific GetNearingExpiration
			if err != nil {
				log.Errorf("error while geting cas: %s", err)
				return
			}

			caScanFunc := func(ca *models.CACertificate) {
				// allowableRotTime := ca.Certificate.Certificate.NotAfter.Add(-time.Duration(ca.IssuanceDuration)).Add(-reenrollableCADelta)
				// now := time.Now()
				// if allowableRotTime.After(now) {
				// 	log.Tracef(
				// 		"not rotating CA %s. Now is %s. Expiration (minus IssuanceDuration and RenewalDelta) is %s. Delta is %s ",
				// 		ca.ID,
				// 		now.Format("2006-01-02 15:04:05"),
				// 		allowableRotTime.Format("2006-01-02 15:04:05"),
				// 		models.DurationToString(allowableRotTime.Sub(now)),
				// 	)
				// } else {
				// 	log.Infof(
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
				// 		log.Errorf("something went wrong while rotating CA: %s", err)
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
		svc.service.GetCertificatesByExpirationDate(GetCertificatesByExpirationDateInput{
			ListInput: ListInput[models.Certificate]{
				QueryParameters: nil,
				ExhaustiveRun:   true,
				ApplyFunc: func(cert *models.Certificate) {
					log.Debugf("updating certificate status from cert with sn '%s' to status '%s'", cert.SerialNumber, models.StatusExpired)
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
					log.Debugf("updating certificate status from cert with sn '%s' to status '%s'", cert.SerialNumber, models.StatusCriticalExpiration)
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
					log.Debugf("updating certificate status from cert with sn '%s' to status '%s'", cert.SerialNumber, models.StatusNearingExpiration)
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
			log.Errorf("could not add scheduled run for checking certificat expiration dates")
		}

		svc.cronInstance.Start()
	}

	return &svc
}

func (svc *CAServiceImpl) SetService(service CAService) {
	svc.service = service
}

func (svc *CAServiceImpl) GetCryptoEngineProvider() (*models.EngineProvider, error) {
	engineInfo := models.EngineProvider{
		ID:                   "-",
		Name:                 "-",
		Metadata:             map[string]interface{}{},
		CryptoEngineProvider: svc.cryptoEngine.GetEngineConfig(),
	}

	return &engineInfo, nil
}

type SignInput struct {
	CAID               string
	Message            []byte
	MessageType        models.SigningMessageType
	SignatureAlgorithm models.SigningAlgorithm
}

func (svc *CAServiceImpl) Sign(input SignInput) ([]byte, error) {
	digest := input.Message
	if input.MessageType == models.RAW {
		digest = input.SignatureAlgorithm.GenerateDigest(input.Message)
	}

	ca, err := svc.GetCAByID(GetCAByIDInput{CAID: input.CAID})
	if err != nil {
		return nil, err
	}

	if ca.KeyMetadata.Type != input.SignatureAlgorithm.GetKeyType() {
		return nil, errs.SentinelAPIError{
			Status: 400,
			Msg:    fmt.Sprintf("incompatible signing hash function. CA uses '%s' key, the selected algorithm is based on '%s'", ca.KeyMetadata.Type.String(), input.SignatureAlgorithm.GetKeyType().String()),
		}
	}

	x509Engine := cryptoengines.NewX509Engine(svc.cryptoEngine, "")
	signer, err := x509Engine.GetCACryptoSigner((*x509.Certificate)(ca.Certificate.Certificate))
	if err != nil {
		return nil, err
	}

	return signer.Sign(rand.Reader, digest, input.SignatureAlgorithm.GetSignerOpts())
}

type VerifySignatureInput struct {
	CAID               string
	Message            []byte
	MessageType        models.SigningMessageType
	Signature          []byte
	SignatureAlgorithm models.SigningAlgorithm
}

func (svc *CAServiceImpl) VerifySignature(input VerifySignatureInput) (bool, error) {
	ca, err := svc.GetCAByID(GetCAByIDInput{CAID: input.CAID})
	if err != nil {
		return false, err
	}

	digest := input.Message
	if input.MessageType == models.RAW {
		digest = input.SignatureAlgorithm.GenerateDigest(input.Message)
	}

	err = input.SignatureAlgorithm.VerifySignature(ca.Certificate.Certificate.PublicKey, digest, input.Signature)
	return err == nil, nil
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

	x509Engine := cryptoengines.NewX509Engine(svc.cryptoEngine, "")

	var caCert *x509.Certificate
	expiration := time.Now()
	if input.CAExpitration.Type == models.Duration {
		expiration.Add(time.Duration(*input.CAExpitration.Duration))
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

func (svc *CAServiceImpl) ImportCA(input ImportCAInput) (*models.CACertificate, error) {
	caCert := input.CACertificate

	valid, err := helpers.ValidateCertAndPrivKey((*x509.Certificate)(caCert), input.CARSAKey, input.CAECKey)
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, fmt.Errorf("CA and the provided key dont match: %w", err)
	}

	engine := svc.cryptoEngine
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

	caID := input.CACertificate.Subject.CommonName
	ca := &models.CACertificate{
		ID: caID,
		CARef: models.CAMetadata{
			Name: input.CACertificate.Subject.CommonName,
			Type: input.CAType,
		},
		Metadata:              map[string]interface{}{},
		IssuanceExpirationRef: input.IssuanceExpiration,
		CreationTS:            caCert.NotBefore,
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
				CAID: caID,
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

func (svc *CAServiceImpl) CreateCA(input CreateCAInput) (*models.CACertificate, error) {
	var err error
	err = validate.Struct(input)
	if err != nil {
		return nil, err
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
	caID := caCert.Subject.CommonName
	ca := models.CACertificate{
		ID:                    caID,
		Metadata:              map[string]interface{}{},
		IssuanceExpirationRef: models.Expiration{
			// Type: ,
		},
		CARef: models.CAMetadata{
			Name: input.Subject.CommonName,
			Type: input.CAType,
		},
		CreationTS: caCert.NotBefore,
		Certificate: models.Certificate{
			Metadata:     map[string]interface{}{},
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

func (svc *CAServiceImpl) GetCAByID(input GetCAByIDInput) (*models.CACertificate, error) {
	err := validate.Struct(input)
	if err != nil {
		return nil, err
	}

	ca, err := svc.caStorage.Select(context.Background(), input.CAID)
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

func (svc *CAServiceImpl) UpdateCAStatus(input UpdateCAStatusInput) (*models.CACertificate, error) {
	err := validate.Struct(input)
	if err != nil {
		return nil, err
	}

	ca, err := svc.caStorage.Select(context.Background(), input.CAID)
	if err != nil {
		return nil, err
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
				log.Errorf("could not revoke certificate %s issued by CA %s", c.SerialNumber, c.IssuerCAMetadata.CAID)
			}
		}

		_, err = svc.certStorage.SelectByCA(context.Background(), ca.CARef.Name, true, revokeCertFunc, &resources.QueryParameters{}, map[string]interface{}{})
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

func (svc *CAServiceImpl) UpdateCAMetadata(input UpdateCAMetadataInput) (*models.CACertificate, error) {
	ca, err := svc.caStorage.Select(context.Background(), input.CAID)
	if err != nil {
		return nil, err
	}

	ca.Metadata = input.Metadata

	return svc.caStorage.Update(context.Background(), ca)
}

type DeleteCAInput struct {
	CAID string `validate:"required"`
}

func (svc *CAServiceImpl) DeleteCA(input DeleteCAInput) error {
	err := validate.Struct(input)
	if err != nil {
		return err
	}

	ca, err := svc.caStorage.Select(context.Background(), input.CAID)
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
		CAID: input.CAID,
	})
	if err != nil {
		return nil, err
	}

	if ca.Status != models.StatusActive {
		return nil, fmt.Errorf("CA is not active")
	}

	x509Engine := cryptoengines.NewX509Engine(svc.cryptoEngine, "")

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

func (svc *CAServiceImpl) GetCertificateBySerialNumber(input GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	err := validate.Struct(input)
	if err != nil {
		return nil, err
	}

	if exists, err := svc.certStorage.Exists(context.Background(), input.SerialNumber); err != nil {
		return nil, err
	} else if !exists {
		return nil, errs.SentinelAPIError{
			Status: http.StatusNotFound,
			Msg:    "",
		}
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
	NewStatus    models.CertificateStatus `validate:"required"`
	// RevocationReason models.RevocationReasonRFC5280
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

	if cert.Status == input.NewStatus {
		return cert, nil
	} else if cert.Status == models.StatusExpired || cert.Status == models.StatusRevoked {
		return nil, ErrStatusTransitionNotAllowed
	} else if cert.Status == models.StatusNearingExpiration && input.NewStatus == models.StatusActive {
		return nil, ErrStatusTransitionNotAllowed
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

func (svc *CAServiceImpl) UpdateCertificateMetadata(input UpdateCertificateMetadataInput) (*models.Certificate, error) {
	cert, err := svc.certStorage.Select(context.Background(), input.SerialNumber)
	if err != nil {
		return nil, err
	}

	cert.Metadata = input.Metadata

	return svc.certStorage.Update(context.Background(), cert)
}
