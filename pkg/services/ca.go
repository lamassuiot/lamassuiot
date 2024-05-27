package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

type CAMiddleware func(CAService) CAService

type CAService interface {
	GetStats(ctx context.Context) (*models.CAStats, error)
	GetStatsByCAID(ctx context.Context, input GetStatsByCAIDInput) (map[models.CertificateStatus]int, error)

	CreateCA(ctx context.Context, input CreateCAInput) (*models.CACertificate, error)
	ImportCA(ctx context.Context, input ImportCAInput) (*models.CACertificate, error)
	GetCAByID(ctx context.Context, input GetCAByIDInput) (*models.CACertificate, error)
	GetCAs(ctx context.Context, input GetCAsInput) (string, error)
	GetCAsByCommonName(ctx context.Context, input GetCAsByCommonNameInput) (string, error)
	UpdateCAStatus(ctx context.Context, input UpdateCAStatusInput) (*models.CACertificate, error)
	UpdateCAMetadata(ctx context.Context, input UpdateCAMetadataInput) (*models.CACertificate, error)
	DeleteCA(ctx context.Context, input DeleteCAInput) error

	SignatureSign(ctx context.Context, input SignatureSignInput) ([]byte, error)
	SignatureVerify(ctx context.Context, input SignatureVerifyInput) (bool, error)

	SignCertificate(ctx context.Context, input SignCertificateInput) (*models.Certificate, error)
	CreateCertificate(ctx context.Context, input CreateCertificateInput) (*models.Certificate, error)
	ImportCertificate(ctx context.Context, input ImportCertificateInput) (*models.Certificate, error)

	GetCertificateBySerialNumber(ctx context.Context, input GetCertificatesBySerialNumberInput) (*models.Certificate, error)
	GetCertificates(ctx context.Context, input GetCertificatesInput) (string, error)
	GetCertificatesByCA(ctx context.Context, input GetCertificatesByCAInput) (string, error)
	GetCertificatesByExpirationDate(ctx context.Context, input GetCertificatesByExpirationDateInput) (string, error)
	GetCertificatesByCaAndStatus(ctx context.Context, input GetCertificatesByCaAndStatusInput) (string, error)
	// GetCertificatesByExpirationDateAndCA(input GetCertificatesByExpirationDateInput) (string, error)
	GetCertificatesByStatus(ctx context.Context, input GetCertificatesByStatusInput) (string, error)
	// GetCertificatesByStatusAndCA(input GetCertificatesByExpirationDateInput) (string, error)
	UpdateCertificateStatus(ctx context.Context, input UpdateCertificateStatusInput) (*models.Certificate, error)
	UpdateCertificateMetadata(ctx context.Context, input UpdateCertificateMetadataInput) (*models.Certificate, error)
}

var validate *validator.Validate

type CAServiceBackend struct {
	service             CAService
	kmsService          KMSService
	caStorage           storage.CACertificatesRepo
	certStorage         storage.CertificatesRepo
	cryptoMonitorConfig config.CryptoMonitoring
	vaServerDomain      string
	logger              *logrus.Entry
}

type CAServiceBuilder struct {
	Logger               *logrus.Entry
	KMSService           KMSService
	CAStorage            storage.CACertificatesRepo
	CertificateStorage   storage.CertificatesRepo
	CryptoMonitoringConf config.CryptoMonitoring
	VAServerDomain       string
}

func NewCAService(builder CAServiceBuilder) (CAService, error) {
	validate = validator.New()

	svc := CAServiceBackend{
		kmsService:          builder.KMSService,
		caStorage:           builder.CAStorage,
		certStorage:         builder.CertificateStorage,
		cryptoMonitorConfig: builder.CryptoMonitoringConf,
		vaServerDomain:      builder.VAServerDomain,
		logger:              builder.Logger,
	}

	svc.service = &svc

	return &svc, nil
}

func (svc *CAServiceBackend) Close() {
	//no op
}

func (svc *CAServiceBackend) SetService(service CAService) {
	svc.service = service
}

func (svc *CAServiceBackend) GetStats(ctx context.Context) (*models.CAStats, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	engines, err := svc.kmsService.GetCryptoEngineProvider(ctx)
	if err != nil {
		lFunc.Errorf("could not get engines: %s", err)
		return nil, err
	}

	lFunc.Debugf("got %d engines", len(engines))

	casDistributionPerEngine := map[string]int{}
	for _, engine := range engines {
		lFunc.Debugf("counting CAs controlled by %s engines", engine.ID)
		ctr, err := svc.caStorage.CountByEngine(ctx, engine.ID)
		if err != nil {
			lFunc.Errorf("could not get CAs for engine %s: %s", engine.ID, err)
			return nil, err
		}
		lFunc.Debugf("got %d CAs", ctr)
		casDistributionPerEngine[engine.ID] = ctr
	}

	casStatus := map[models.CertificateStatus]int{}
	for _, status := range []models.CertificateStatus{models.StatusActive, models.StatusExpired, models.StatusRevoked} {
		lFunc.Debugf("counting certificates in %s status", status)
		ctr, err := svc.caStorage.CountByStatus(ctx, status)
		if err != nil {
			lFunc.Errorf("could not count certificates in %s status: %s", status, err)
			return nil, err
		}
		lFunc.Debugf("got %d certificates", ctr)

		casStatus[status] = ctr
	}

	lFunc.Debugf("counting total number of CAs")
	totalCAs, err := svc.caStorage.Count(ctx)
	if err != nil {
		lFunc.Errorf("could not count total number of CAs: %s", err)
		return nil, err
	}

	lFunc.Debugf("counting total number of certificates")
	totalCerts, err := svc.certStorage.Count(ctx)
	if err != nil {
		lFunc.Errorf("could not count total number of certificates: %s", err)
		return nil, err
	}

	return &models.CAStats{
		CACertificatesStats: models.CACertificatesStats{
			TotalCAs:                 totalCAs,
			CAsDistributionPerEngine: casDistributionPerEngine,
			CAsStatus:                casStatus,
		},
		CertificatesStats: models.CertificatesStats{
			TotalCertificates:            totalCerts,
			CertificateDistributionPerCA: map[string]int{},
			CertificateStatus:            map[models.CertificateStatus]int{},
		},
	}, nil
}

type GetStatsByCAIDInput struct {
	CAID string
}

func (svc *CAServiceBackend) GetStatsByCAID(ctx context.Context, input GetStatsByCAIDInput) (map[models.CertificateStatus]int, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	stats := map[models.CertificateStatus]int{}
	for _, status := range []models.CertificateStatus{models.StatusActive, models.StatusExpired, models.StatusRevoked} {
		lFunc.Debugf("counting certificates in %s status", status)
		ctr, err := svc.certStorage.CountByCAIDAndStatus(ctx, input.CAID, status)
		if err != nil {
			lFunc.Errorf("could not count certificates in %s status: %s", status, err)
			return nil, err
		}

		lFunc.Debugf("got %d certificates", ctr)
		stats[status] = ctr
	}

	return stats, nil
}

type issueCAInput struct {
	ParentCA     *models.CACertificate
	KeyMetadata  models.KeyMetadata     `validate:"required"`
	Subject      models.Subject         `validate:"required"`
	CAType       models.CertificateType `validate:"required"`
	CAExpiration models.Expiration
	EngineID     string
	CAID         string `validate:"required"`
}

type issueCAOutput struct {
	Certificate *x509.Certificate
}

func (svc *CAServiceBackend) issueCA(ctx context.Context, input issueCAInput) (*issueCAOutput, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)
	var err error

	expiration := time.Now()
	if input.CAExpiration.Type == models.Duration {
		expiration = expiration.Add(time.Duration(*input.CAExpiration.Duration))
	} else {
		expiration = *input.CAExpiration.Time
	}

	caKey, err := svc.kmsService.CreatePrivateKey(ctx, CreatePrivateKeyInput{
		EngineID:     input.EngineID,
		KeyAlgorithm: input.KeyMetadata.Type,
		KeySize:      input.KeyMetadata.Bits,
	})
	if err != nil {
		lFunc.Errorf("could not create CA %s private key: %s", input.Subject.CommonName, err)
		return nil, err
	}

	aki := caKey.KeyID
	ski := caKey.KeyID
	if input.ParentCA != nil {
		aki = string(input.ParentCA.Certificate.Certificate.SubjectKeyId)
	}

	caPubKey, err := helpers.PublicKeyPEMToCryptoKey(caKey.PublicKey)
	if err != nil {
		return nil, err
	}

	caSigner, err := NewKMSCryptoSigner(caKey.EngineID, string(caKey.KeyID), svc.kmsService)
	if err != nil {
		err := fmt.Errorf("could not get KMS Crypto Signer for CA: %s", err)
		lFunc.Errorf(err.Error())
		return nil, err
	}

	now := time.Now()
	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))
	template := x509.Certificate{
		IsCA:           true,
		SerialNumber:   sn,
		Subject:        helpers.SubjectToPkixName(input.Subject),
		AuthorityKeyId: []byte(aki),
		SubjectKeyId:   []byte(ski),
		OCSPServer: []string{
			fmt.Sprintf("%s/ocsp", svc.vaServerDomain),
		},
		CRLDistributionPoints: []string{
			fmt.Sprintf("%s/crl/%s", svc.vaServerDomain, ski),
		},
		NotBefore:             now,
		NotAfter:              expiration,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsage(x509.ExtKeyUsageOCSPSigning),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	var caCert *x509.Certificate
	if input.ParentCA == nil {
		lFunc.Debugf("creating root CA certificate. common name: %s. key type: %s. key bits: %d", input.Subject.CommonName, input.KeyMetadata.Type, input.KeyMetadata.Bits)
		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, caPubKey, caSigner)
		if err != nil {
			err := fmt.Errorf("could not create root CA: %s", err)
			lFunc.Errorf(err.Error())
			return nil, err
		}

		caCert, err = x509.ParseCertificate(derBytes)
		if err != nil {
			lFunc.Errorf(err.Error())
			return nil, err
		}
	} else {
		parentKey, err := svc.kmsService.GetKey(ctx, GetKeyInput{
			EngineID: input.ParentCA.EngineID,
			KeyID:    string(input.ParentCA.Certificate.Certificate.SubjectKeyId),
		})
		if err != nil {
			lFunc.Errorf(err.Error())
			return nil, err
		}

		parentSigner, err := NewKMSCryptoSigner(input.ParentCA.EngineID, parentKey.KeyID, svc.kmsService)
		if err != nil {
			return nil, err
		}

		lFunc.Debugf("creating subordinate CA certificate. common name: %s. key type: %s. key bits: %d", input.Subject.CommonName, input.KeyMetadata.Type, input.KeyMetadata.Bits)
		derBytes, err := x509.CreateCertificate(rand.Reader, &template, (*x509.Certificate)(input.ParentCA.Certificate.Certificate), caPubKey, parentSigner)
		if err != nil {
			lFunc.Errorf("something went wrong while creating CA '%s' Certificate: %s", input.Subject.CommonName, err)
			return nil, err
		}

		caCert, err = x509.ParseCertificate(derBytes)
		if err != nil {
			lFunc.Errorf(err.Error())
			return nil, err
		}
	}

	return &issueCAOutput{
		Certificate: caCert,
	}, nil
}

type ImportCAInput struct {
	ID                 string
	CAType             models.CertificateType    `validate:"required,ne=MANAGED"`
	IssuanceExpiration models.Expiration         `validate:"required"`
	CACertificate      *models.X509Certificate   `validate:"required"`
	CAChain            []*models.X509Certificate //Parent CAs. They MUST be sorted as follows. 0: Root-CA; 1: Subordinate CA from Root-CA; ...
	CARSAKey           *rsa.PrivateKey
	CAECKey            *ecdsa.PrivateKey
	KeyType            models.KeyType
	EngineID           string
	ParentID           string
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
func (svc *CAServiceBackend) ImportCA(ctx context.Context, input ImportCAInput) (*models.CACertificate, error) {
	var err error

	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	validate.RegisterStructValidation(importCAValidation, ImportCAInput{})
	err = validate.Struct(input)
	if err != nil {
		lFunc.Errorf("ImportCA struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	} else {
		lFunc.Tracef("ImportCA struct validation success")
	}

	caCert := input.CACertificate
	var engineID string
	if input.CAType != models.CertificateTypeExternal {
		lFunc.Debugf("importing CA %s - %s  private key. CA type: %s", helpers.SerialNumberToString(input.CACertificate.SerialNumber), input.CACertificate.Subject.CommonName, input.CAType)
		if input.CARSAKey != nil {
			// _, err := svc.kmsService.ImportRSAPrivateKey(input.EngineID, input.CARSAKey, x509engines.CryptoAssetLRI(x509engines.CertificateAuthority, helpers.SerialNumberToString(input.CACertificate.SerialNumber)))
			if err != nil {
				lFunc.Errorf("could not imported  %s private key: %s", helpers.SerialNumberToString(input.CACertificate.SerialNumber), err)
				return nil, fmt.Errorf("could not import key: %w", err)
			}
		} else if input.CAECKey != nil {
			// _, err = svc.kmsService.ImportECDSAPrivateKey(input.EngineID, input.CAECKey, x509engines.CryptoAssetLRI(x509engines.CertificateAuthority, helpers.SerialNumberToString(input.CACertificate.SerialNumber)))
		} else {
			lFunc.Errorf("key type %s not supported", input.KeyType)
			return nil, fmt.Errorf("KeyType not supported")
		}

		if err != nil {
			lFunc.Errorf("could not import CA %s private key: %s", helpers.SerialNumberToString(input.CACertificate.SerialNumber), err)
			return nil, fmt.Errorf("could not import key: %w", err)
		}
	}

	caID := input.ID
	if caID == "" {
		caID = goid.NewV4UUID().String()
	}

	var parentCA *models.CACertificate
	if input.ParentID != "" {
		parentCA, err = svc.service.GetCAByID(ctx, GetCAByIDInput{
			CAID: input.ParentID,
		})
		if err != nil {
			return nil, fmt.Errorf("parent CA not found: %w", err)
		}
	}

	issuerMeta := models.IssuerCAMetadata{
		ID:           caID,
		SerialNumber: helpers.SerialNumberToString(input.CACertificate.SerialNumber),
		Level:        0,
	}
	level := 0

	if parentCA != nil {
		level = parentCA.Level + 1
		issuerMeta = models.IssuerCAMetadata{
			ID:           input.ParentID,
			SerialNumber: parentCA.SerialNumber,
			Level:        parentCA.Level,
		}
	}

	ca := &models.CACertificate{
		ID:                    caID,
		Type:                  input.CAType,
		Metadata:              map[string]interface{}{},
		IssuanceExpirationRef: input.IssuanceExpiration,
		CreationTS:            time.Now(),
		Level:                 level,
		Certificate: models.Certificate{
			Certificate:         input.CACertificate,
			Status:              models.StatusActive,
			SerialNumber:        helpers.SerialNumberToString(caCert.SerialNumber),
			KeyMetadata:         helpers.KeyStrengthMetadataFromCertificate((*x509.Certificate)(caCert)),
			Subject:             helpers.PkixNameToSubject(caCert.Subject),
			ValidFrom:           caCert.NotBefore,
			ValidTo:             caCert.NotAfter,
			RevocationTimestamp: time.Time{},
			Metadata:            map[string]interface{}{},
			Type:                input.CAType,
			IssuerCAMetadata:    issuerMeta,
			EngineID:            engineID,
		},
	}

	lFunc.Debugf("insert CA %s in storage engine", caID)
	return svc.caStorage.Insert(ctx, ca)
}

type CreateCAInput struct {
	ID                 string
	ParentID           string
	KeyMetadata        models.KeyMetadata `validate:"required"`
	Subject            models.Subject     `validate:"required"`
	IssuanceExpiration models.Expiration  `validate:"required"`
	CAExpiration       models.Expiration  `validate:"required"`
	EngineID           string
	Metadata           map[string]any
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
func (svc *CAServiceBackend) CreateCA(ctx context.Context, input CreateCAInput) (*models.CACertificate, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)
	if input.Metadata == nil {
		input.Metadata = map[string]any{}
	}

	var err error
	validate.RegisterStructValidation(createCAValidation, CreateCAInput{})
	err = validate.Struct(input)
	if err != nil {
		lFunc.Errorf("CreateCAInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	var parentCA *models.CACertificate
	if input.ParentID != "" {
		lFunc.Infof("request includes a parent CA id: %s", input.ParentID)
		exists, ca, err := svc.caStorage.SelectExistsByID(ctx, input.ParentID)
		if err != nil {
			lFunc.Errorf("could not check if parent CA %s exists: %s", input.ParentID, err)
			return nil, err
		}

		if !exists {
			lFunc.Errorf("parent CA %s does not exist", input.ParentID)
		}

		lFunc.Debugf("parent CA %s exists", input.ParentID)

		parentCA = ca
		var caExpiration time.Time

		if input.IssuanceExpiration.Type == models.Duration {
			caExpiration = time.Now().Add((time.Duration)(*input.CAExpiration.Duration))
		} else {
			caExpiration = *input.CAExpiration.Time
		}
		parentCaExpiration := parentCA.Certificate.ValidTo

		if parentCaExpiration.Before(caExpiration) {
			lFunc.Errorf("requested CA would expire after parent CA")
			return nil, fmt.Errorf("invalid expiration")
		}

		lFunc.Debugf("subordinated CA  expires before parent CA")

	}

	caID := input.ID
	if caID == "" {
		caID = goid.NewV4UUID().String()
	}

	exists, _, err := svc.caStorage.SelectExistsByID(ctx, caID)
	if err != nil {
		lFunc.Errorf("could not check if CA %s exists: %s", caID, err)
		return nil, err
	}

	if exists {
		lFunc.Errorf("cannot create duplicate CA. CA with ID '%s' already exists:", caID)
		return nil, errs.ErrCAAlreadyExists
	}

	lFunc.Debugf("creating CA with common name: %s", input.Subject.CommonName)
	issuedCA, err := svc.issueCA(ctx, issueCAInput{
		ParentCA:     parentCA,
		KeyMetadata:  input.KeyMetadata,
		Subject:      input.Subject,
		CAType:       models.CertificateTypeManaged,
		CAExpiration: input.CAExpiration,
		EngineID:     input.EngineID,
		CAID:         caID,
	})
	if err != nil {
		lFunc.Errorf("could not create CA %s certificate: %s", input.Subject.CommonName, err)
		return nil, err
	}

	var engineID string
	if input.EngineID == "" {
		engineID = ""
		engines, err := svc.kmsService.GetCryptoEngineProvider(ctx)
		if err != nil {
			return nil, err
		}

		for _, engine := range engines {
			if engine.Default {
				engineID = engine.ID
				break
			}
		}
	} else {
		engineID = input.EngineID
	}

	caCert := issuedCA.Certificate
	caLevel := 0
	issuerCAMeta := models.IssuerCAMetadata{
		SerialNumber: helpers.SerialNumberToString(caCert.SerialNumber),
		ID:           caID,
		Level:        0,
	}

	if parentCA != nil {
		caLevel = parentCA.Level + 1
		issuerCAMeta = models.IssuerCAMetadata{
			SerialNumber: parentCA.SerialNumber,
			ID:           parentCA.ID,
			Level:        parentCA.Level,
		}
	}

	ca := models.CACertificate{
		ID:                    caID,
		Metadata:              input.Metadata,
		Type:                  models.CertificateTypeManaged,
		IssuanceExpirationRef: input.IssuanceExpiration,
		CreationTS:            time.Now(),
		Level:                 caLevel,
		Certificate: models.Certificate{
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
			IssuerCAMetadata:    issuerCAMeta,
			Metadata:            map[string]interface{}{},
			Type:                models.CertificateTypeManaged,
			EngineID:            engineID,
		},
	}

	lFunc.Debugf("insert CA %s in storage engine", caID)
	return svc.caStorage.Insert(ctx, &ca)
}

type GetCAByIDInput struct {
	CAID string `validate:"required"`
}

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceBackend) GetCAByID(ctx context.Context, input GetCAByIDInput) (*models.CACertificate, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("GetCAByIDInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if CA '%s' exists", input.CAID)
	exists, ca, err := svc.caStorage.SelectExistsByID(ctx, input.CAID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA '%s' exists in storage engine: %s", input.CAID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("CA %s can not be found in storage engine", input.CAID)
		return nil, errs.ErrCANotFound
	}

	return ca, err
}

type GetCAsInput struct {
	QueryParameters *resources.QueryParameters

	ExhaustiveRun bool //wether to iter all elems
	ApplyFunc     func(ca models.CACertificate)
}

func (svc *CAServiceBackend) GetCAs(ctx context.Context, input GetCAsInput) (string, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	nextBookmark, err := svc.caStorage.SelectAll(ctx, storage.StorageListRequest[models.CACertificate]{
		ExhaustiveRun: input.ExhaustiveRun,
		ApplyFunc:     input.ApplyFunc,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     nil,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while reading all CAs from storage engine: %s", err)
		return "", err
	}

	return nextBookmark, nil
}

type GetCABySerialNumberInput struct {
	SerialNumber string `validate:"required"`
}

func (svc *CAServiceBackend) GetCABySerialNumber(ctx context.Context, input GetCABySerialNumberInput) (*models.CACertificate, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("GetCABySerialNumber struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if CA '%s' exists", input.SerialNumber)
	exists, ca, err := svc.caStorage.SelectExistsBySerialNumber(ctx, input.SerialNumber)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA '%s' exists in storage engine: %s", input.SerialNumber, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("CA %s can not be found in storage engine", input.SerialNumber)
		return nil, errs.ErrCANotFound
	}

	return ca, nil
}

type GetCAsByCommonNameInput struct {
	CommonName string

	QueryParameters *resources.QueryParameters
	ExhaustiveRun   bool //wether to iter all elems
	ApplyFunc       func(cert models.CACertificate)
}

func (svc *CAServiceBackend) GetCAsByCommonName(ctx context.Context, input GetCAsByCommonNameInput) (string, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Debugf("reading CAs by %s common name", input.CommonName)
	nextBookmark, err := svc.caStorage.SelectByCommonName(ctx, input.CommonName, storage.StorageListRequest[models.CACertificate]{
		ExhaustiveRun: input.ExhaustiveRun,
		ApplyFunc:     input.ApplyFunc,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     nil,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while reading all CAs by Common name %s from storage engine: %s", input.CommonName, err)
		return "", err
	}

	return nextBookmark, err
}

type UpdateCAStatusInput struct {
	CAID             string                   `validate:"required"`
	Status           models.CertificateStatus `validate:"required"`
	RevocationReason models.RevocationReason
}

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
//   - ErrCAAlreadyRevoked
//     CA already revoked
func (svc *CAServiceBackend) UpdateCAStatus(ctx context.Context, input UpdateCAStatusInput) (*models.CACertificate, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateCAStatusInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if CA '%s' exists", input.CAID)
	exists, ca, err := svc.caStorage.SelectExistsByID(ctx, input.CAID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA '%s' exists in storage engine: %s", input.CAID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("CA %s can not be found in storage engine", input.CAID)
		return nil, errs.ErrCANotFound
	}

	if ca.Status == models.StatusExpired {
		lFunc.Errorf("cannot update an expired CA certificate")
		return nil, errs.ErrCertificateStatusTransitionNotAllowed
	}

	if ca.Status == models.StatusRevoked && ca.RevocationReason != ocsp.CertificateHold {
		lFunc.Errorf("cannot update a revoke CA certificate in %s status. Only a revoked CA certificate with reason '6 - CertificateHold' can be unrevoked", ca.RevocationReason.String())
		return nil, errs.ErrCertificateStatusTransitionNotAllowed
	}

	ca.Status = input.Status
	if ca.Status == models.StatusRevoked {
		rrb, _ := input.RevocationReason.MarshalText()
		lFunc.Infof("CA %s is being revoked with revocation reason %d - %s", input.CAID, input.RevocationReason, string(rrb))
		ca.RevocationReason = input.RevocationReason
		ca.RevocationTimestamp = time.Now()
	}

	lFunc.Debugf("updating the status of CA %s to %s", input.CAID, input.Status)
	ca, err = svc.caStorage.Update(ctx, ca)
	if err != nil {
		lFunc.Errorf("could not update CA %s status: %s", input.CAID, err)
		return nil, err
	}

	if input.Status == models.StatusRevoked {
		revokeCAFunc := func(ca models.CACertificate) {
			_, err := svc.service.UpdateCAStatus(ctx, UpdateCAStatusInput{
				CAID:             ca.ID,
				Status:           models.StatusRevoked,
				RevocationReason: ocsp.CessationOfOperation,
			})
			if err != nil {
				lFunc.Errorf("could not revoke child CA Certificate %s issued by CA %s", ca.ID, ca.IssuerCAMetadata.ID)
			}
		}

		_, err := svc.caStorage.SelectByParentCA(ctx, ca.ID, storage.StorageListRequest[models.CACertificate]{
			ExhaustiveRun: true,
			ApplyFunc:     revokeCAFunc,
			QueryParams:   &resources.QueryParameters{},
			ExtraOpts:     nil,
		})
		if err != nil {
			return nil, err
		}

		ctr := 0
		revokeCertFunc := func(c models.Certificate) {
			lFunc.Infof("\n\n%d - %s\n\n", ctr, c.SerialNumber)
			ctr++
			_, err := svc.service.UpdateCertificateStatus(ctx, UpdateCertificateStatusInput{
				SerialNumber:     c.SerialNumber,
				NewStatus:        models.StatusRevoked,
				RevocationReason: ocsp.CessationOfOperation,
			})
			if err != nil {
				lFunc.Errorf("could not revoke certificate %s issued by CA %s", c.SerialNumber, c.IssuerCAMetadata.ID)
			}
		}

		_, err = svc.certStorage.SelectByCA(ctx, ca.ID, storage.StorageListRequest[models.Certificate]{
			ExhaustiveRun: true,
			ApplyFunc:     revokeCertFunc,
			QueryParams:   &resources.QueryParameters{},
			ExtraOpts:     map[string]interface{}{},
		})
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
func (svc *CAServiceBackend) UpdateCAMetadata(ctx context.Context, input UpdateCAMetadataInput) (*models.CACertificate, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateCAMetadataInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if CA '%s' exists", input.CAID)
	exists, ca, err := svc.caStorage.SelectExistsByID(ctx, input.CAID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA '%s' exists in storage engine: %s", input.CAID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("CA %s can not be found in storage engine", input.CAID)
		return nil, errs.ErrCANotFound
	}

	ca.Metadata = input.Metadata

	lFunc.Debugf("updating %s CA metadata", input.CAID)
	return svc.caStorage.Update(ctx, ca)
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
func (svc *CAServiceBackend) DeleteCA(ctx context.Context, input DeleteCAInput) error {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("DeleteCA struct validation error: %s", err)
		return errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if CA '%s' exists", input.CAID)
	exists, ca, err := svc.caStorage.SelectExistsByID(ctx, input.CAID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA '%s' exists in storage engine: %s", input.CAID, err)
		return err
	}

	if !exists {
		lFunc.Errorf("CA %s can not be found in storage engine", input.CAID)
		return errs.ErrCANotFound
	}

	if ca.Status != models.StatusExpired && ca.Status != models.StatusRevoked {
		lFunc.Errorf("CA %s can not be deleted while in status %s", input.CAID, ca.Status)
		return errs.ErrCAStatus
	}

	err = svc.caStorage.Delete(ctx, input.CAID)
	if err != nil {
		lFunc.Errorf("something went wrong while deleting the CA %s %s", input.CAID, err)
		return err
	}
	return err
}

type SignCertificateInput struct {
	CAID         string                         `validate:"required"`
	CertRequest  *models.X509CertificateRequest `validate:"required"`
	Subject      *models.Subject
	SignVerbatim bool
}

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
//   - ErrCAStatus
//     CA is not active
func (svc *CAServiceBackend) SignCertificate(ctx context.Context, input SignCertificateInput) (*models.Certificate, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("SignCertificateInput struct validation error: %s", err)
		return nil, errs.ErrCANotFound
	}

	lFunc.Debugf("checking if CA '%s' exists", input.CAID)
	exists, ca, err := svc.caStorage.SelectExistsByID(ctx, input.CAID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA '%s' exists in storage engine: %s", input.CAID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("CA %s can not be found in storage engine", input.CAID)
		return nil, errs.ErrCANotFound
	}

	if ca.Status != models.StatusActive {
		lFunc.Errorf("%s CA is not active", ca.ID)
		return nil, errs.ErrCAStatus
	}

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

	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))
	now := time.Now()
	certificateTemplate := x509.Certificate{
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		AuthorityKeyId:     caCert.SubjectKeyId,
		SerialNumber:       sn,
		Issuer:             caCert.Subject,
		Subject:            csr.Subject,
		NotBefore:          now,
		NotAfter:           expiration,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		OCSPServer: []string{
			fmt.Sprintf("https://%s/api/va/ocsp", svc.vaServerDomain),
		},
		CRLDistributionPoints: []string{
			fmt.Sprintf("https://%s/api/va/crl/%s", svc.vaServerDomain, string(caCert.SubjectKeyId)),
		},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	caSigner, err := NewKMSCryptoSigner(ca.EngineID, string(caCert.SubjectKeyId), svc.kmsService)
	if err != nil {
		err := fmt.Errorf("could not get KMS Crypto Signer for CA: %s", err)
		lFunc.Errorf(err.Error())
		return nil, err
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, caCert, csr.PublicKey, caSigner)
	if err != nil {
		err := fmt.Errorf("could not sign certificate: %s", err)
		lFunc.Errorf(err.Error())
		return nil, err
	}

	certificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		err := fmt.Errorf("could not parse signed certificate %s", err)
		lFunc.Errorf(err.Error())
		return nil, err
	}

	cert := models.Certificate{
		Metadata:    map[string]interface{}{},
		Type:        models.CertificateTypeExternal,
		Certificate: (*models.X509Certificate)(certificate),
		IssuerCAMetadata: models.IssuerCAMetadata{
			SerialNumber: helpers.SerialNumberToString(caCert.SerialNumber),
			ID:           ca.ID,
		},
		Status:              models.StatusActive,
		KeyMetadata:         helpers.KeyStrengthMetadataFromCertificate(certificate),
		Subject:             helpers.PkixNameToSubject(certificate.Subject),
		SerialNumber:        helpers.SerialNumberToString(certificate.SerialNumber),
		ValidFrom:           certificate.NotBefore,
		ValidTo:             certificate.NotAfter,
		RevocationTimestamp: time.Time{},
	}
	lFunc.Debugf("insert Certificate %s in storage engine", cert.SerialNumber)
	return svc.certStorage.Insert(ctx, &cert)
}

type CreateCertificateInput struct {
	KeyMetadata models.KeyMetadata `validate:"required"`
	Subject     models.Subject     `validate:"required"`
}

func (svc *CAServiceBackend) CreateCertificate(ctx context.Context, input CreateCertificateInput) (*models.Certificate, error) {
	return nil, fmt.Errorf("TODO")
}

type ImportCertificateInput struct {
	ImportMode  models.CertificateType
	Certificate *models.X509Certificate
	Metadata    map[string]any
}

func (svc *CAServiceBackend) ImportCertificate(ctx context.Context, input ImportCertificateInput) (*models.Certificate, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	status := models.StatusActive
	if input.Certificate.NotAfter.Before(time.Now()) {
		status = models.StatusExpired
	}

	newCert := models.Certificate{
		Metadata:            input.Metadata,
		Type:                models.CertificateTypeExternal,
		Certificate:         (*models.X509Certificate)(input.Certificate),
		Status:              status,
		KeyMetadata:         helpers.KeyStrengthMetadataFromCertificate((*x509.Certificate)(input.Certificate)),
		Subject:             helpers.PkixNameToSubject(input.Certificate.Subject),
		SerialNumber:        helpers.SerialNumberToString(input.Certificate.SerialNumber),
		ValidFrom:           input.Certificate.NotBefore,
		ValidTo:             input.Certificate.NotAfter,
		RevocationTimestamp: time.Time{},
	}

	var parentCA *models.CACertificate
	svc.caStorage.SelectByCommonName(ctx, input.Certificate.Issuer.CommonName, storage.StorageListRequest[models.CACertificate]{
		ExhaustiveRun: true,
		ApplyFunc: func(ca models.CACertificate) {
			err := helpers.ValidateCertificate((*x509.Certificate)(ca.Certificate.Certificate), (*x509.Certificate)(input.Certificate), false)
			if err == nil {
				parentCA = &ca
			}
		},
	})

	if parentCA != nil {
		newCert.IssuerCAMetadata = models.IssuerCAMetadata{
			SerialNumber: parentCA.SerialNumber,
			ID:           parentCA.ID,
			Level:        parentCA.Level,
		}
	} else {
		newCert.IssuerCAMetadata = models.IssuerCAMetadata{
			SerialNumber: "-",
			ID:           "-",
			Level:        -1,
		}
	}

	cert, err := svc.certStorage.Insert(ctx, &newCert)
	if err != nil {
		lFunc.Errorf("could not insert certificate: %s", err)
		return nil, err
	}

	return cert, nil
}

type SignatureSignInput struct {
	CAID             string                 `validate:"required"`
	Message          []byte                 `validate:"required"`
	MessageType      models.SignMessageType `validate:"required"`
	SigningAlgorithm string                 `validate:"required"`
}

func (svc *CAServiceBackend) SignatureSign(ctx context.Context, input SignatureSignInput) ([]byte, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("ImportCertificate struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}
	lFunc.Debugf("checking if CA '%s' exists", input.CAID)
	exists, ca, err := svc.caStorage.SelectExistsByID(ctx, input.CAID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA '%s' exists in storage engine: %s", input.CAID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("CA %s can not be found in storage engine", input.CAID)
		return nil, errs.ErrCANotFound
	}

	signature, err := svc.kmsService.Sign(ctx, SignInput{
		EngineID:         ca.EngineID,
		KeyID:            string(ca.Certificate.Certificate.SubjectKeyId),
		Message:          input.Message,
		MessageType:      input.MessageType,
		SigningAlgorithm: input.SigningAlgorithm,
	})
	if err != nil {
		return nil, err
	}

	return signature, nil
}

type SignatureVerifyInput struct {
	CAID             string                 `validate:"required"`
	Signature        []byte                 `validate:"required"`
	Message          []byte                 `validate:"required"`
	MessageType      models.SignMessageType `validate:"required"`
	SigningAlgorithm string                 `validate:"required"`
}

func (svc *CAServiceBackend) SignatureVerify(ctx context.Context, input SignatureVerifyInput) (bool, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("SignatureVerifyInput struct validation error: %s", err)
		return false, errs.ErrValidateBadRequest
	}
	lFunc.Debugf("checking if CA '%s' exists", input.CAID)
	exists, ca, err := svc.caStorage.SelectExistsByID(ctx, input.CAID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA '%s' exists in storage engine: %s", input.CAID, err)
		return false, err
	}

	if !exists {
		lFunc.Errorf("CA %s can not be found in storage engine", input.CAID)
		return false, errs.ErrCANotFound
	}

	valid, err := svc.kmsService.Verify(ctx, VerifyInput{
		EngineID:         ca.EngineID,
		KeyID:            string(ca.Certificate.Certificate.SubjectKeyId),
		Message:          input.Message,
		MessageType:      input.MessageType,
		SigningAlgorithm: input.SigningAlgorithm,
		Signature:        input.Signature,
	})
	if err != nil {
		return false, err
	}

	return valid, nil
}

type GetCertificatesBySerialNumberInput struct {
	SerialNumber string `validate:"required"`
}

// Returned Error Codes:
//   - ErrCertificateNotFound
//     The specified Certificate can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceBackend) GetCertificateBySerialNumber(ctx context.Context, input GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("GetCertificatesBySerialNumberInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if Certificate '%s' exists", input.SerialNumber)
	exists, cert, err := svc.certStorage.SelectExistsBySerialNumber(ctx, input.SerialNumber)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if Certificate '%s' exists in storage engine: %s", input.SerialNumber, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("certificate %s can not be found in storage engine", input.SerialNumber)
		return nil, errs.ErrCertificateNotFound
	}

	return cert, nil
}

type GetCertificatesInput struct {
	resources.ListInput[models.Certificate]
}

func (svc *CAServiceBackend) GetCertificates(ctx context.Context, input GetCertificatesInput) (string, error) {
	return svc.certStorage.SelectAll(ctx, storage.StorageListRequest[models.Certificate]{
		ExhaustiveRun: input.ExhaustiveRun,
		ApplyFunc:     input.ApplyFunc,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     nil,
	})
}

type GetCertificatesByCAInput struct {
	CAID string `validate:"required"`
	resources.ListInput[models.Certificate]
}

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceBackend) GetCertificatesByCA(ctx context.Context, input GetCertificatesByCAInput) (string, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("GetCertificatesByCAInput struct validation error: %s", err)
		return "", errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if CA '%s' exists", input.CAID)
	exists, _, err := svc.caStorage.SelectExistsByID(ctx, input.CAID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA '%s' exists in storage engine: %s", input.CAID, err)
		return "", err
	}

	if !exists {
		lFunc.Errorf("CA %s can not be found in storage engine", input.CAID)
		return "", errs.ErrCANotFound
	}

	lFunc.Debugf("reading certificates by %s CA", input.CAID)
	return svc.certStorage.SelectByCA(ctx, input.CAID, storage.StorageListRequest[models.Certificate]{
		ExhaustiveRun: input.ExhaustiveRun,
		ApplyFunc:     input.ApplyFunc,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     nil,
	})
}

type GetCertificatesByExpirationDateInput struct {
	ExpiresAfter  time.Time
	ExpiresBefore time.Time
	resources.ListInput[models.Certificate]
}

func (svc *CAServiceBackend) GetCertificatesByExpirationDate(ctx context.Context, input GetCertificatesByExpirationDateInput) (string, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Debugf("reading certificates by expiration date. expiresafter: %s. expiresbefore: %s", input.ExpiresAfter, input.ExpiresBefore)
	return svc.certStorage.SelectByExpirationDate(ctx, input.ExpiresBefore, input.ExpiresAfter, storage.StorageListRequest[models.Certificate]{
		ExhaustiveRun: input.ExhaustiveRun,
		ApplyFunc:     input.ApplyFunc,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     nil,
	})
}

type GetCertificatesByCaAndStatusInput struct {
	CAID   string
	Status models.CertificateStatus
	resources.ListInput[models.Certificate]
}

func (svc *CAServiceBackend) GetCertificatesByCaAndStatus(ctx context.Context, input GetCertificatesByCaAndStatusInput) (string, error) {
	return svc.certStorage.SelectByCAIDAndStatus(ctx, input.CAID, input.Status, storage.StorageListRequest[models.Certificate]{
		ExhaustiveRun: input.ExhaustiveRun,
		ApplyFunc:     input.ApplyFunc,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     nil,
	})
}

type GetCertificatesByStatusInput struct {
	Status models.CertificateStatus
	resources.ListInput[models.Certificate]
}

func (svc *CAServiceBackend) GetCertificatesByStatus(ctx context.Context, input GetCertificatesByStatusInput) (string, error) {
	return svc.certStorage.SelectByStatus(ctx, input.Status, storage.StorageListRequest[models.Certificate]{
		ExhaustiveRun: input.ExhaustiveRun,
		ApplyFunc:     input.ApplyFunc,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     nil,
	})
}

type UpdateCertificateStatusInput struct {
	SerialNumber     string                   `validate:"required"`
	NewStatus        models.CertificateStatus `validate:"required"`
	RevocationReason models.RevocationReason
}

// Returned Error Codes:
//   - ErrCertificateNotFound
//     The specified Certificate can not be found in the Database
//   - ErrCertificateStatusTransitionNotAllowed
//     The specified status is not valid for this certficate due to its initial status
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceBackend) UpdateCertificateStatus(ctx context.Context, input UpdateCertificateStatusInput) (*models.Certificate, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateCertificateStatus struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if certificate '%s' exists", input.SerialNumber)
	exists, cert, err := svc.certStorage.SelectExistsBySerialNumber(ctx, input.SerialNumber)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if certificate '%s' exists in storage engine: %s", input.SerialNumber, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("certificate %s can not be found in storage engine", input.SerialNumber)
		return nil, errs.ErrCertificateNotFound
	}

	if cert.Status == models.StatusExpired {
		lFunc.Errorf("cannot update an expired certificate")
		return nil, errs.ErrCertificateStatusTransitionNotAllowed
	}

	if cert.Status == models.StatusRevoked && cert.RevocationReason != ocsp.CertificateHold {
		lFunc.Errorf("cannot update a revoke certificate in %s status. Only a revoked certificate with reason '6 - CertificateHold' can be unrevoked", cert.RevocationReason.String())
		return nil, errs.ErrCertificateStatusTransitionNotAllowed
	}

	cert.Status = input.NewStatus

	if input.NewStatus == models.StatusRevoked {
		rrb, _ := input.RevocationReason.MarshalText()
		lFunc.Infof("certificate with SN %s issued by CA with ID %s and CN %s is being revoked with revocation reason %d - %s", input.SerialNumber, cert.IssuerCAMetadata.ID, cert.Certificate.Issuer.CommonName, input.RevocationReason, string(rrb))
		cert.RevocationReason = input.RevocationReason
		cert.RevocationTimestamp = time.Now()
	} else {
		//Make sure to reset revocation TS in case of reactivation
		cert.RevocationTimestamp = time.Time{}
	}

	lFunc.Debugf("updating %s certificate status to %s", input.SerialNumber, input.NewStatus)
	return svc.certStorage.Update(ctx, cert)
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
func (svc *CAServiceBackend) UpdateCertificateMetadata(ctx context.Context, input UpdateCertificateMetadataInput) (*models.Certificate, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateCertificateMetadataInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if certificate '%s' exists", input.SerialNumber)
	exists, cert, err := svc.certStorage.SelectExistsBySerialNumber(ctx, input.SerialNumber)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if certificate '%s' exists in storage engine: %s", input.SerialNumber, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("certificate %s can not be found in storage engine", input.SerialNumber)
		return nil, errs.ErrCertificateNotFound
	}

	cert.Metadata = input.Metadata
	lFunc.Debugf("updating %s certificate metadata", input.SerialNumber)
	return svc.certStorage.Update(ctx, cert)
}

func createCAValidation(sl validator.StructLevel) {
	ca := sl.Current().Interface().(CreateCAInput)
	if !helpers.ValidateExpirationTimeRef(ca.CAExpiration) {
		// lFunc.Errorf("CA Expiration time ref is incompatible with the selected variable")
		sl.ReportError(ca.CAExpiration, "CAExpiration", "CAExpiration", "InvalidCAExpiration", "")
	}

	if !helpers.ValidateExpirationTimeRef(ca.IssuanceExpiration) {
		// lFunc.Errorf("issuance expiration time ref is incompatible with the selected variable")
		sl.ReportError(ca.IssuanceExpiration, "IssuanceExpiration", "IssuanceExpiration", "InvalidIssuanceExpiration", "")
	}

	expiration := time.Now()
	if ca.CAExpiration.Type == models.Duration {
		expiration = expiration.Add(time.Duration(*ca.CAExpiration.Duration))
	} else {
		expiration = *ca.CAExpiration.Time
	}

	if !helpers.ValidateCAExpiration(ca.IssuanceExpiration, expiration) {
		// lFunc.Errorf("issuance expiration is greater than the CA expiration")
		sl.ReportError(ca.IssuanceExpiration, "IssuanceExpiration", "IssuanceExpiration", "IssuanceExpirationGreaterThanCAExpiration", "")
	}
}

func importCAValidation(sl validator.StructLevel) {
	ca := sl.Current().Interface().(ImportCAInput)
	caCert := ca.CACertificate

	if ca.CAType != models.CertificateTypeExternal {
		if !helpers.ValidateCAExpiration(ca.IssuanceExpiration, caCert.NotAfter) {
			// lFunc.Errorf("issuance expiration is greater than the CA expiration")
			sl.ReportError(ca.IssuanceExpiration, "IssuanceExpiration", "IssuanceExpiration", "IssuanceExpirationGreaterThanCAExpiration", "")
		}
		// lFunc.Debugf("CA Type: %s", ca.CAType)
		if !helpers.ValidateExpirationTimeRef(ca.IssuanceExpiration) {
			// lFunc.Errorf("expiration time ref is incompatible with the selected variable")
			sl.ReportError(ca.IssuanceExpiration, "IssuanceExpiration", "IssuanceExpiration", "InvalidIssuanceExpiration", "")
		}

		valid, err := helpers.ValidateCertAndPrivKey((*x509.Certificate)(caCert), ca.CARSAKey, ca.CAECKey)
		if err != nil {
			sl.ReportError(ca.CARSAKey, "CARSAKey", "CARSAKey", "PrivateKeyAndCertificateNotMatch", "")
			sl.ReportError(ca.CAECKey, "CAECKey", "CAECKey", "PrivateKeyAndCertificateNotMatch", "")
		}

		if !valid {
			// lFunc.Errorf("CA certificate and the private key provided are not compatible")
			sl.ReportError(ca.CARSAKey, "CARSAKey", "CARSAKey", "PrivateKeyAndCertificateNotMatch", "")
			sl.ReportError(ca.CAECKey, "CAECKey", "CAECKey", "PrivateKeyAndCertificateNotMatch", "")
		}
	}
}
