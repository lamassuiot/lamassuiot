package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
	"unicode"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/x509engines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	"github.com/sirupsen/logrus"

	"golang.org/x/crypto/ocsp"
)

type CAMiddleware func(services.CAService) services.CAService

var validate *validator.Validate

type Engine struct {
	Default bool
	Service cryptoengines.CryptoEngine
}

type CAServiceBackend struct {
	service               services.CAService
	cryptoEngines         map[string]*cryptoengines.CryptoEngine
	defaultCryptoEngine   *cryptoengines.CryptoEngine
	defaultCryptoEngineID string
	//caStorage                   storage.CACertificatesRepo
	certStorage                 storage.CertificatesRepo
	caCertificateRequestStorage storage.CACertificateRequestRepo
	vaServerDomains             []string
	logger                      *logrus.Entry
}

type CAServiceBuilder struct {
	Logger        *logrus.Entry
	CryptoEngines map[string]*Engine
	//CAStorage                   storage.CACertificatesRepo
	CertificateStorage          storage.CertificatesRepo
	CACertificateRequestStorage storage.CACertificateRequestRepo
	VAServerDomains             []string
}

func NewCAService(builder CAServiceBuilder) (services.CAService, error) {
	validate = validator.New()

	engines := map[string]*cryptoengines.CryptoEngine{}
	var defaultCryptoEngine *cryptoengines.CryptoEngine
	var defaultCryptoEngineID string

	for engineID, engineInstance := range builder.CryptoEngines {
		engines[engineID] = &engineInstance.Service
		if engineInstance.Default {
			defaultCryptoEngine = &engineInstance.Service
			defaultCryptoEngineID = engineID
		}

		// Check if engine keys should be renamed
		keyIDs, err := engineInstance.Service.ListPrivateKeyIDs()
		if err != nil {
			return nil, fmt.Errorf("could not list private keys for engine %s: %s", engineID, err)
		}

		keyMigLog := builder.Logger.WithField("engine", engineID)
		softCrypto := software.NewSoftwareCryptoEngine(keyMigLog)
		keyMigLog.Infof("checking engine keys format")

		for _, keyID := range keyIDs {
			// check if they are in V1 format (serial number).
			// V2 format is the hex encoded SHA256 of the public key, a string of 64 characters
			containsNonHex := false
			for _, char := range keyID {
				if !unicode.IsLetter(char) && !unicode.IsDigit(char) {
					// Not a hex character. Exit loop
					containsNonHex = true
					break
				}
			}

			if len(keyID) != 64 || containsNonHex {
				// Transform to V2 format
				key, err := engineInstance.Service.GetPrivateKeyByID(keyID)
				if err != nil {
					return nil, fmt.Errorf("could not get key %s: %w", keyID, err)
				}

				newKeyID, err := softCrypto.EncodePKIXPublicKeyDigest(key.Public())
				if err != nil {
					return nil, fmt.Errorf("could not encode public key digest: %w", err)
				}

				keyMigLog.Debugf("renaming key %s to %s", keyID, newKeyID)
				err = engineInstance.Service.RenameKey(keyID, newKeyID)
				if err != nil {
					return nil, fmt.Errorf("could not rename key %s: %w", keyID, err)
				}
			}
		}
	}

	if defaultCryptoEngine == nil {
		return nil, fmt.Errorf("could not find the default crypto engine")
	}

	svc := CAServiceBackend{
		cryptoEngines:         engines,
		defaultCryptoEngine:   defaultCryptoEngine,
		defaultCryptoEngineID: defaultCryptoEngineID,
		//caStorage:                   builder.CAStorage,
		certStorage:                 builder.CertificateStorage,
		caCertificateRequestStorage: builder.CACertificateRequestStorage,
		vaServerDomains:             builder.VAServerDomains,
		logger:                      builder.Logger,
	}

	svc.service = &svc

	return &svc, nil
}

func (svc *CAServiceBackend) Close() {
	//no op
}

func (svc *CAServiceBackend) SetService(service services.CAService) {
	svc.service = service
}

func (svc *CAServiceBackend) GetStats(ctx context.Context) (*models.CAStats, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	engines, err := svc.GetCryptoEngineProvider(ctx)
	if err != nil {
		lFunc.Errorf("could not get engines: %s", err)
		return nil, err
	}

	lFunc.Debugf("got %d engines", len(engines))

	casDistributionPerEngine := map[string]int{}
	for _, engine := range engines {
		lFunc.Debugf("counting CAs controlled by %s engines", engine.ID)
		ctr, err := svc.certStorage.CountCAByEngine(ctx, engine.ID)
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
		ctr, err := svc.certStorage.CountCAByStatus(ctx, status)
		if err != nil {
			lFunc.Errorf("could not count certificates in %s status: %s", status, err)
			return nil, err
		}
		lFunc.Debugf("got %d certificates", ctr)

		casStatus[status] = ctr
	}

	lFunc.Debugf("counting total number of CAs")
	totalCAs, err := svc.certStorage.CountCA(ctx)
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

func (svc *CAServiceBackend) GetStatsByCAID(ctx context.Context, input services.GetStatsByCAIDInput) (map[models.CertificateStatus]int, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	stats := map[models.CertificateStatus]int{}
	for _, status := range []models.CertificateStatus{models.StatusActive, models.StatusExpired, models.StatusRevoked} {
		lFunc.Debugf("counting certificates in %s status", status)
		ctr, err := svc.certStorage.CountByCAIDAndStatus(ctx, input.SubjectKeyID, status)
		if err != nil {
			lFunc.Errorf("could not count certificates in %s status: %s", status, err)
			return nil, err
		}

		lFunc.Debugf("got %d certificates", ctr)
		stats[status] = ctr
	}

	return stats, nil
}

func (svc *CAServiceBackend) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
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

// Generate a Key Pair and a CSR for a future CA
func (svc *CAServiceBackend) RequestCACSR(ctx context.Context, input services.RequestCAInput) (*models.CACertificateRequest, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)
	if input.Metadata == nil {
		input.Metadata = map[string]any{}
	}

	var err error
	validate.RegisterStructValidation(createCAValidation, services.CreateCAInput{})
	err = validate.Struct(input)
	if err != nil {
		lFunc.Errorf("RequestCAInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	engineID, engine, err := svc.getCryptoEngine(input.EngineID)
	if err != nil {
		lFunc.Errorf("could not get engine ID %s: %s", input.EngineID, err)
	}

	keyID, csrSigner, err := engine.GenerateKeyPair(ctx, input.KeyMetadata)
	if err != nil {
		lFunc.Errorf("could not generate CA %s private key: %s", input.Subject.CommonName, err)
		return nil, err
	}

	csr, err := engine.GenerateCertificateRequest(ctx, csrSigner, input.Subject)
	if err != nil {
		lFunc.Errorf("could not generate CA %s CSR: %s", input.Subject.CommonName, err)
		return nil, err
	}

	caCSRModel := models.CACertificateRequest{
		ID:          time.Now().String(),
		Metadata:    input.Metadata,
		CreationTS:  time.Now(),
		KeyId:       keyID,
		Subject:     input.Subject,
		Status:      models.StatusRequestPending,
		EngineID:    engineID,
		KeyMetadata: helpers.KeyStrengthBuilder(input.KeyMetadata.Type, input.KeyMetadata.Bits),
		Fingerprint: chelpers.ComputePublicKeyFingerprint(csr),
		CSR:         models.X509CertificateRequest(*csr),
	}

	lFunc.Debugf("insert CA Request %s in storage engine", keyID)
	return svc.caCertificateRequestStorage.Insert(ctx, &caCSRModel)
}

func (svc *CAServiceBackend) CreateCA(ctx context.Context, input services.CreateCAInput) (*models.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)
	if input.Metadata == nil {
		input.Metadata = map[string]any{}
	}

	var err error
	validate.RegisterStructValidation(createCAValidation, services.CreateCAInput{})
	err = validate.Struct(input)
	if err != nil {
		lFunc.Errorf("CreateCAInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lFunc.Debugf("creating CA with common name: %s", input.Subject.CommonName)
	engineID, engine, err := svc.getCryptoEngine(input.EngineID)
	if err != nil {
		lFunc.Errorf("could not get engine %s: %s", input.EngineID, err)
	}

	// Generate Key Pair to be used by the new CA
	keyID, signer, err := engine.GenerateKeyPair(ctx, input.KeyMetadata)
	if err != nil {
		lFunc.Errorf("could not generate CA %s private key: %s", input.Subject.CommonName, err)
		return nil, err
	}

	var ca *x509.Certificate
	var caLevel int
	var issuerCAMeta models.IssuerCAMetadata

	skid := helpers.FormatHexWithColons([]byte(keyID))
	akid := skid
	// Check if CA is Root (self-signed) or Subordinate (signed by another CA). Non self-signed/root CAs require a parent CA
	if input.ParentID == "" {
		// Root CA. Root CAs can be generate directly
		ca, err = engine.CreateRootCA(ctx, signer, keyID, input.Subject, input.CAExpiration)
		if err != nil {
			lFunc.Errorf("could not create CA %s certificate: %s", input.Subject.CommonName, err)
			return nil, err
		}

		caLevel = 0
		issuerCAMeta = models.IssuerCAMetadata{
			SN:    helpers.SerialNumberToString(ca.SerialNumber),
			ID:    skid,
			Level: 0,
		}
	} else {
		// Subordinate CA. Before creating a subordinate CA, it is required to check if the parent CA exists
		exists, parentCA, err := svc.certStorage.SelectExistsCAByID(ctx, input.ParentID)
		if err != nil {
			lFunc.Errorf("could not check if parent CA %s exists: %s", input.ParentID, err)
			return nil, err
		}

		if !exists {
			lFunc.Errorf("parent CA %s does not exist", input.ParentID)
			return nil, errs.ErrCANotFound
		}

		akid = parentCA.SubjectKeyID

		var caExpiration time.Time
		if input.CAExpiration.Type == models.Duration {
			caExpiration = time.Now().Add((time.Duration)(input.CAExpiration.Duration))
		} else {
			caExpiration = input.CAExpiration.Time
		}

		parentCaExpiration := parentCA.ValidTo
		if parentCaExpiration.Before(caExpiration) {
			lFunc.Errorf("requested CA would expire after parent CA")
			return nil, fmt.Errorf("invalid expiration")
		}

		lFunc.Debugf("valid expiration. Subordinated CA expires before parent CA")

		// Generate a new Key Pair and a CSR for the CA
		caCSR, err := svc.RequestCACSR(ctx, services.RequestCAInput{
			KeyMetadata: input.KeyMetadata,
			Subject:     input.Subject,
			EngineID:    engineID,
			Metadata:    input.Metadata,
		})
		if err != nil {
			lFunc.Errorf("could not create CA %s CSR: %s", input.Subject.CommonName, err)
			return nil, err
		}

		signedCA, err := svc.SignCertificate(ctx, services.SignCertificateInput{
			SubjectKeyID:    input.ParentID,
			CertRequest:     &caCSR.CSR,
			IssuanceProfile: engine.GetDefaultCAIssuanceProfile(ctx, input.CAExpiration),
		})
		if err != nil {
			lFunc.Errorf("could not sign CA %s certificate: %s", input.Subject.CommonName, err)
			return nil, err
		}

		ca = (*x509.Certificate)(signedCA.Certificate)

		// Update the CA level and issuer metadata
		caLevel = parentCA.Level + 1
		issuerCAMeta = models.IssuerCAMetadata{
			SN:    parentCA.SerialNumber,
			ID:    parentCA.SubjectKeyID,
			Level: parentCA.Level,
		}
	}

	if err != nil {
		lFunc.Errorf("could not create CA %s certificate: %s", input.Subject.CommonName, err)
		return nil, err
	}

	caCert := models.Certificate{
		SubjectKeyID:   skid,
		AuthorityKeyID: akid,
		Certificate:    (*models.X509Certificate)(ca),
		Status:         models.StatusActive,
		SerialNumber:   helpers.SerialNumberToString(ca.SerialNumber),
		KeyMetadata: models.KeyStrengthMetadata{
			Type:     input.KeyMetadata.Type,
			Bits:     input.KeyMetadata.Bits,
			Strength: models.KeyStrengthHigh,
		},
		Subject:             input.Subject,
		ValidFrom:           ca.NotBefore,
		ValidTo:             ca.NotAfter,
		RevocationTimestamp: time.Time{},
		IssuerCAMetadata:    issuerCAMeta,
		Metadata:            input.Metadata,
		Type:                models.CertificateTypeManaged,
		EngineID:            engineID,
		IsCA:                true,
		Level:               caLevel,
	}

	lFunc.Debugf("insert CA %s in storage engine", skid)
	return svc.certStorage.Insert(ctx, &caCert)
}

func (svc *CAServiceBackend) getCryptoEngine(engineId string) (string, x509engines.X509Engine, error) {
	availableEngineId := svc.defaultCryptoEngineID
	if engineId != "" {
		_, ok := svc.cryptoEngines[engineId]
		if !ok {
			return "", x509engines.X509Engine{}, errs.ErrCryptoEngineNotFound
		}
		availableEngineId = engineId
	}

	return availableEngineId, x509engines.NewX509Engine(svc.logger, svc.cryptoEngines[availableEngineId], svc.vaServerDomains), nil
}

func (svc *CAServiceBackend) GetCARequests(ctx context.Context, input services.GetItemsInput[models.CACertificateRequest]) (string, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	nextBookmark, err := svc.caCertificateRequestStorage.SelectAll(ctx, storage.StorageListRequest[models.CACertificateRequest]{
		ExhaustiveRun: input.ExhaustiveRun,
		ApplyFunc:     input.ApplyFunc,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     nil,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while reading all Requests from storage engine: %s", err)
		return "", err
	}

	return nextBookmark, nil
}

func (svc *CAServiceBackend) GetCARequestByID(ctx context.Context, input services.GetByIDInput) (*models.CACertificateRequest, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("GetByIDInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if CA Request '%s' exists", input.ID)
	exists, caReq, err := svc.caCertificateRequestStorage.SelectExistsByID(ctx, input.ID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA Request '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("CA Request %s can not be found in storage engine", input.ID)
		return nil, errs.ErrCANotFound
	}

	return caReq, err
}

// DeleteCARequestByID deletes a CA Request by ID
func (svc *CAServiceBackend) DeleteCARequestByID(ctx context.Context, input services.GetByIDInput) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("DeleteCAByIDInput struct validation error: %s", err)
		return errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if CA Request '%s' exists", input.ID)
	exists, _, err := svc.caCertificateRequestStorage.SelectExistsByID(ctx, input.ID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA Request '%s' exists in storage engine: %s", input.ID, err)
		return err
	}

	if !exists {
		lFunc.Errorf("CA Request %s can not be found in storage engine", input.ID)
		return errs.ErrCANotFound
	}

	lFunc.Debugf("deleting CA Request %s from storage engine", input.ID)
	err = svc.caCertificateRequestStorage.Delete(ctx, input.ID)
	if err != nil {
		lFunc.Errorf("something went wrong while deleting CA Request '%s' from storage engine: %s", input.ID, err)
		return err
	}

	return nil
}

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceBackend) GetCAByID(ctx context.Context, input services.GetCAByIDInput) (*models.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("GetByIDInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if CA '%s' exists", input.SubjectKeyID)
	exists, ca, err := svc.certStorage.SelectExistsCAByID(ctx, input.SubjectKeyID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA '%s' exists in storage engine: %s", input.SubjectKeyID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("CA %s can not be found in storage engine", input.SubjectKeyID)
		return nil, errs.ErrCANotFound
	}

	return ca, err
}

func (svc *CAServiceBackend) GetCAs(ctx context.Context, input services.GetCAsInput) (string, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	nextBookmark, err := svc.certStorage.SelectAll(ctx, storage.StorageListRequest[models.Certificate]{
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

func (svc *CAServiceBackend) GetCABySerialNumber(ctx context.Context, input services.GetCABySerialNumberInput) (*models.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("GetCABySerialNumber struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if CA '%s' exists", input.SerialNumber)
	exists, ca, err := svc.certStorage.SelectExistsCABySerialNumber(ctx, input.SerialNumber)
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

func (svc *CAServiceBackend) GetCAsByCommonName(ctx context.Context, input services.GetCAsByCommonNameInput) (string, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Debugf("reading CAs by %s common name", input.CommonName)
	nextBookmark, err := svc.certStorage.SelectCAByCommonName(ctx, input.CommonName, storage.StorageListRequest[models.Certificate]{
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

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
//   - ErrCAAlreadyRevoked
//     CA already revoked
func (svc *CAServiceBackend) UpdateCAStatus(ctx context.Context, input services.UpdateCAStatusInput) (*models.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateCAStatusInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if CA '%s' exists", input.SubjectKeyID)
	exists, ca, err := svc.certStorage.SelectExistsCAByID(ctx, input.SubjectKeyID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA '%s' exists in storage engine: %s", input.SubjectKeyID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("CA %s can not be found in storage engine", input.SubjectKeyID)
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
		lFunc.Infof("CA %s is being revoked with revocation reason %d - %s", input.SubjectKeyID, input.RevocationReason, string(rrb))
		ca.RevocationReason = input.RevocationReason
		ca.RevocationTimestamp = time.Now()
	}

	lFunc.Debugf("updating the status of CA %s to %s", input.SubjectKeyID, input.Status)
	ca, err = svc.certStorage.Update(ctx, ca)
	if err != nil {
		lFunc.Errorf("could not update CA %s status: %s", input.SubjectKeyID, err)
		return nil, err
	}

	if input.Status == models.StatusRevoked {
		revokeCAFunc := func(ca models.Certificate) {
			_, err := svc.service.UpdateCAStatus(ctx, services.UpdateCAStatusInput{
				SubjectKeyID:     ca.SubjectKeyID,
				Status:           models.StatusRevoked,
				RevocationReason: ocsp.CessationOfOperation,
			})
			if err != nil {
				lFunc.Errorf("could not revoke child CA Certificate %s issued by CA %s", ca.SubjectKeyID, ca.IssuerCAMetadata.ID)
			}
		}

		_, err := svc.certStorage.SelectCAByParentCA(ctx, ca.SubjectKeyID, storage.StorageListRequest[models.Certificate]{
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
			_, err := svc.service.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
				SerialNumber:     c.SerialNumber,
				NewStatus:        models.StatusRevoked,
				RevocationReason: ocsp.CessationOfOperation,
			})
			if err != nil {
				lFunc.Errorf("could not revoke certificate %s issued by CA %s", c.SerialNumber, c.IssuerCAMetadata.ID)
			}
		}

		_, err = svc.certStorage.SelectByCA(ctx, ca.SubjectKeyID, storage.StorageListRequest[models.Certificate]{
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

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceBackend) UpdateCAMetadata(ctx context.Context, input services.UpdateCAMetadataInput) (*models.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateCAMetadataInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if CA '%s' exists", input.SubjectKeyID)
	exists, ca, err := svc.certStorage.SelectExistsCAByID(ctx, input.SubjectKeyID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA '%s' exists in storage engine: %s", input.SubjectKeyID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("CA %s can not be found in storage engine", input.SubjectKeyID)
		return nil, errs.ErrCANotFound
	}

	updatedMetadata, err := chelpers.ApplyPatches(ca.Metadata, input.Patches)
	if err != nil {
		lFunc.Errorf("failed to apply patches to metadata for CA '%s': %v", input.SubjectKeyID, err)
		return nil, err
	}

	ca.Metadata = updatedMetadata

	lFunc.Debugf("updating %s CA metadata", input.SubjectKeyID)
	return svc.certStorage.Update(ctx, ca)
}

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
//   - ErrCAStatus
//     Cannot delete a CA that is not expired or revoked.
func (svc *CAServiceBackend) DeleteCA(ctx context.Context, input services.DeleteCAInput) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("DeleteCA struct validation error: %s", err)
		return errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if CA '%s' exists", input.SubjectKeyID)
	exists, ca, err := svc.certStorage.SelectExistsCAByID(ctx, input.SubjectKeyID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA '%s' exists in storage engine: %s", input.SubjectKeyID, err)
		return err
	}

	if !exists {
		lFunc.Errorf("CA %s can not be found in storage engine", input.SubjectKeyID)
		return errs.ErrCANotFound
	}

	if ca.Type == models.CertificateTypeExternal {
		lFunc.Debugf("External CA can be deleted. Proceeding")
	} else if ca.Status == models.StatusExpired || ca.Status == models.StatusRevoked {
		lFunc.Debugf("Expired or revoked CA can be deleted. Proceeding")
	} else {
		lFunc.Errorf("CA %s can not be deleted while in status %s", input.SubjectKeyID, ca.Status)
		return errs.ErrCAStatus
	}

	ctr := 0
	revokeCertFunc := func(c models.Certificate) {
		lFunc.Infof("\n\n%d - %s\n\n", ctr, c.SerialNumber)
		ctr++
		_, err := svc.service.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
			SerialNumber:     c.SerialNumber,
			NewStatus:        models.StatusRevoked,
			RevocationReason: ocsp.CessationOfOperation,
		})
		if err != nil {
			lFunc.Errorf("could not revoke certificate %s issued by CA %s: %s", c.SerialNumber, c.IssuerCAMetadata.ID, err)
		}
	}
	_, err = svc.certStorage.SelectByCA(ctx, ca.SubjectKeyID, storage.StorageListRequest[models.Certificate]{
		ExhaustiveRun: true,
		ApplyFunc:     revokeCertFunc,
		QueryParams: &resources.QueryParameters{
			Filters: []resources.FilterOption{
				{
					Field:           "status",
					FilterOperation: resources.StringNotEqual,
					Value:           string(models.StatusRevoked),
				},
				{
					Field:           "status",
					FilterOperation: resources.StringNotEqual,
					Value:           string(models.StatusExpired),
				},
			},
		},
		ExtraOpts: map[string]interface{}{},
	})
	if err != nil {
		lFunc.Errorf("could not revoke certificate %s issued by CA %s", ca.Certificate.SerialNumber, ca.IssuerCAMetadata.ID)
	}
	err = svc.certStorage.DeleteCA(ctx, input.SubjectKeyID)
	if err != nil {
		lFunc.Errorf("something went wrong while deleting the CA %s %s", input.SubjectKeyID, err)
		return err
	}

	return err
}

func (svc *CAServiceBackend) SignCertificate(ctx context.Context, input services.SignCertificateInput) (*models.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("SignCertificateInput struct validation error: %s", err)
		return nil, errs.ErrCANotFound
	}

	lFunc.Debugf("checking if CA '%s' exists", input.SubjectKeyID)
	exists, ca, err := svc.certStorage.SelectExistsCAByID(ctx, input.SubjectKeyID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA '%s' exists in storage engine: %s", input.SubjectKeyID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("CA %s can not be found in storage engine", input.SubjectKeyID)
		return nil, errs.ErrCANotFound
	}

	if ca.Status != models.StatusActive {
		lFunc.Errorf("%s CA is not active", ca.SubjectKeyID)
		return nil, errs.ErrCAStatus
	}

	engine := svc.cryptoEngines[ca.EngineID]
	x509Engine := x509engines.NewX509Engine(lFunc, engine, svc.vaServerDomains)

	caCert := (*x509.Certificate)(ca.Certificate)
	csr := (*x509.CertificateRequest)(input.CertRequest)

	caCertSigner, err := x509Engine.GetCertificateSigner(ctx, caCert)
	if err != nil {
		lFunc.Errorf("could not get CA %s signer: %s", caCert.Subject.CommonName, err)
		return nil, err
	}

	lFunc.Debugf("sign certificate request with %s CA and %s crypto engine", input.SubjectKeyID, x509Engine.GetEngineConfig().Provider)
	x509Cert, err := x509Engine.SignCertificateRequest(ctx, csr, caCert, caCertSigner, input.IssuanceProfile)
	if err != nil {
		lFunc.Errorf("could not sign certificate request with %s CA", caCert.Subject.CommonName)
		return nil, err
	}

	cert := models.Certificate{
		Metadata:    map[string]interface{}{},
		Type:        models.CertificateTypeExternal,
		Certificate: (*models.X509Certificate)(x509Cert),
		IssuerCAMetadata: models.IssuerCAMetadata{
			SN: helpers.SerialNumberToString(caCert.SerialNumber),
			ID: ca.SubjectKeyID,
		},
		Status:              models.StatusActive,
		KeyMetadata:         helpers.KeyStrengthMetadataFromCertificate(x509Cert),
		Subject:             chelpers.PkixNameToSubject(x509Cert.Subject),
		Issuer:              chelpers.PkixNameToSubject(x509Cert.Issuer),
		SerialNumber:        helpers.SerialNumberToString(x509Cert.SerialNumber),
		ValidFrom:           x509Cert.NotBefore,
		ValidTo:             x509Cert.NotAfter,
		RevocationTimestamp: time.Time{},
		IsCA:                x509Cert.IsCA,
		SubjectKeyID:        helpers.FormatHexWithColons(x509Cert.SubjectKeyId),
		AuthorityKeyID:      helpers.FormatHexWithColons(x509Cert.AuthorityKeyId),
		EngineID:            "",
	}

	// CAs get inserted into the CA storage engine by the CreateCA method. Don't insert them here.
	if !x509Cert.IsCA {
		lFunc.Debugf("insert Certificate %s in storage engine", cert.SerialNumber)
		return svc.certStorage.Insert(ctx, &cert)
	}

	return &cert, nil
}

// Generate a new Key Pair and Sign a CSR to create a new Certificate. The Keys are stored and can later be used to sign other material.
func (svc *CAServiceBackend) CreateCertificate(ctx context.Context, input services.CreateCertificateInput) (*models.Certificate, error) {
	// Generate a new Key Pair

	// use svc.SignCertificate to sign the

	//update the certificate with the KeyID and EngineID
	return nil, fmt.Errorf("TODO")
}

// ImportCertificateOrCA dynamically imports either a certificate or a CA.
func (svc *CAServiceBackend) ImportCertificate(ctx context.Context, input services.ImportCertificateInput) (*models.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	validate.RegisterStructValidation(importCertificateValidation, services.ImportCertificateInput{})
	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("ImportCertificate struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	} else {
		lFunc.Tracef("ImportCertificate struct validation success")
	}

	// Convert input certificate to X.509
	x509Cert := input.Certificate
	if x509Cert == nil {
		return nil, errors.New("invalid certificate")
	}

	issuer := chelpers.PkixNameToSubject(x509Cert.Issuer)

	skid := helpers.FormatHexWithColons(x509Cert.SubjectKeyId)
	akid := helpers.FormatHexWithColons(x509Cert.AuthorityKeyId)
	issuerMeta := models.IssuerCAMetadata{
		ID:    akid,
		SN:    "-",
		Level: 0,
	}
	level := 0

	isSelfSigned := helpers.IsSelfSignedCertificate(akid, skid, x509Cert)

	if !isSelfSigned {
		var parentCAs []models.Certificate

		svc.certStorage.SelectCABySubjectAndSubjectKeyID(ctx, issuer, akid,
			storage.StorageListRequest[models.Certificate]{
				ExhaustiveRun: true,
				ApplyFunc: func(c models.Certificate) {
					parentCAs = append(parentCAs, c)
				},
			})

		// Iterate over parent CAs to verify and assign values when found
		for _, parentCA := range parentCAs {
			p := x509.Certificate(*parentCA.Certificate)
			c := x509.Certificate(*x509Cert)
			err = c.CheckSignatureFrom(&p)

			if err != nil {
				if akid != "" {
					lFunc.Warnf("possible parent CA detected, but failed cryptographic validation: %s", err)
				}
				continue // Skip if verification fails
			}

			// When verification is successful, update the level and metadata
			level = parentCA.Level + 1
			issuerMeta = models.IssuerCAMetadata{
				ID:    parentCA.SubjectKeyID,
				SN:    parentCA.SerialNumber,
				Level: parentCA.Level,
			}

			break
		}
	} else {
		issuerMeta = models.IssuerCAMetadata{
			ID:    skid,
			SN:    helpers.SerialNumberToString(input.Certificate.SerialNumber),
			Level: 0,
		}
		// Verify that the parent CA signed the certificate
		p := x509.Certificate(*x509Cert)
		err = p.CheckSignatureFrom(&p)
		if err != nil {
			lFunc.Errorf("parent CA did not sign the certificate: %s", err)
			return nil, fmt.Errorf("parent CA did not sign the certificate: %w", err)
		}
	}

	keyImported := false

	// Handle Key Import if a private key is provided
	if input.PrivateKey != nil {
		lFunc.Debugf("Importing private key for %s", x509Cert.Subject.CommonName)

		var engine cryptoengines.CryptoEngine
		var err error

		if input.EngineID == "" {
			engine = *svc.defaultCryptoEngine
			lFunc.Infof("Using default crypto engine for key import")
		} else {
			engine = *svc.cryptoEngines[input.EngineID]
			if engine == nil {
				lFunc.Errorf("Engine ID %s not configured", input.EngineID)
				return nil, fmt.Errorf("engine ID %s not configured", input.EngineID)
			}
		}

		// Import the key based on type
		switch x509Cert.PublicKeyAlgorithm {
		case x509.RSA:
			privateKey, ok := input.PrivateKey.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("invalid RSA private key")
			}
			_, _, err = engine.ImportRSAPrivateKey(privateKey)
		case x509.ECDSA:
			privateKey, ok := input.PrivateKey.(*ecdsa.PrivateKey)
			if !ok {
				return nil, errors.New("invalid ECDSA private key")
			}
			_, _, err = engine.ImportECDSAPrivateKey(privateKey)
		default:
			lFunc.Errorf("Key type %s not supported", x509Cert.PublicKeyAlgorithm.String())
			return nil, fmt.Errorf("key type %s not supported", x509Cert.PublicKeyAlgorithm.String())
		}

		if err != nil {
			lFunc.Errorf("Could not import private key: %s", err)
			return nil, fmt.Errorf("could not import key: %w", err)
		}
		keyImported = true
	}

	// Determine certificate status
	status := models.StatusActive
	if x509Cert.NotAfter.Before(time.Now()) {
		status = models.StatusExpired
	}

	typ := models.CertificateTypeExternal
	if keyImported {
		typ = models.CertificateTypeImportedWithKey
	}

	// Create a new certificate record
	newCert := &models.Certificate{
		SerialNumber:        helpers.SerialNumberToString(x509Cert.SerialNumber),
		SubjectKeyID:        helpers.FormatHexWithColons(x509Cert.SubjectKeyId),
		AuthorityKeyID:      helpers.FormatHexWithColons(x509Cert.AuthorityKeyId),
		Status:              status,
		Certificate:         (*models.X509Certificate)(x509Cert),
		KeyMetadata:         helpers.KeyStrengthMetadataFromCertificate(x509Cert),
		Subject:             chelpers.PkixNameToSubject(x509Cert.Subject),
		Issuer:              chelpers.PkixNameToSubject(x509Cert.Issuer),
		ValidFrom:           x509Cert.NotBefore,
		ValidTo:             x509Cert.NotAfter,
		IssuerCAMetadata:    issuerMeta,
		EngineID:            input.EngineID,
		Type:                typ,
		RevocationTimestamp: time.Time{},
		IsCA:                x509Cert.IsCA,
		Level:               level,
	}

	newCert, err = svc.certStorage.Insert(ctx, newCert)
	if err != nil {
		lFunc.Errorf("could not insert certificate: %s", err)
		return nil, err
	}

	if x509Cert.IsCA {
		// Flag to check if it's the first iteration
		firstIteration := true
		queue := []models.Certificate{*newCert}

		for len(queue) > 0 {
			parent := queue[0]
			queue = queue[1:] // Dequeue

			// In the future if we plan to support Cross Signed certs, it is important not fetching just by AKI,
			// since two cross signed certs (using the same SKI) are signed by different AKIs. Hence, we select by AKI AND Issuer DSN
			svc.certStorage.SelectCAByIssuerAndAuthorityKeyID(ctx, parent.Subject, parent.SubjectKeyID, storage.StorageListRequest[models.Certificate]{
				ExhaustiveRun: true,
				ApplyFunc: func(child models.Certificate) {
					isSelfSignedChild := helpers.IsSelfSignedCertificate(child.AuthorityKeyID, child.SubjectKeyID, (*x509.Certificate)(input.Certificate))

					if !isSelfSignedChild {
						if firstIteration { //Check also with crypto validation to ensure child is actually signed by parent?
							p := x509.Certificate(*parent.Certificate)
							c := x509.Certificate(*child.Certificate)
							err = c.CheckSignatureFrom(&p)

							if err != nil {
								if child.AuthorityKeyID != "" {
									lFunc.Warnf("possible child CA detected, but failed cryptographic validation: %s", err)
								}
								return // if verification fails, "tentative" parent CA did not sign the certificate being imported. skip update
							}
						}

						// We are certain the parent CA did sign the certificate being imported
						child.Level = parent.Level + 1
						child.IssuerCAMetadata.ID = parent.SubjectKeyID
						child.IssuerCAMetadata.Level = parent.Level
						child.IssuerCAMetadata.SN = parent.SerialNumber

						// Update the level in DB
						svc.certStorage.Update(ctx, &child)

						// Enqueue child for further processing
						queue = append(queue, child)
					}
				},
			})
			firstIteration = false
		}

	}

	return newCert, nil
}

func (svc *CAServiceBackend) SignatureSign(ctx context.Context, input services.SignatureSignInput) ([]byte, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("ImportCertificate struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}
	lFunc.Debugf("checking if CA '%s' exists", input.SubjectKeyID)
	exists, ca, err := svc.certStorage.SelectExistsCAByID(ctx, input.SubjectKeyID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA '%s' exists in storage engine: %s", input.SubjectKeyID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("CA %s can not be found in storage engine", input.SubjectKeyID)
		return nil, errs.ErrCANotFound
	}

	engine := svc.cryptoEngines[ca.EngineID]
	x509Engine := x509engines.NewX509Engine(lFunc, engine, svc.vaServerDomains)
	lFunc.Debugf("sign signature with %s CA and %s crypto engine", input.SubjectKeyID, x509Engine.GetEngineConfig().Provider)
	signature, err := x509Engine.Sign(ctx, (*x509.Certificate)(ca.Certificate), input.Message, input.MessageType, input.SigningAlgorithm)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (svc *CAServiceBackend) SignatureVerify(ctx context.Context, input services.SignatureVerifyInput) (bool, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("SignatureVerifyInput struct validation error: %s", err)
		return false, errs.ErrValidateBadRequest
	}
	lFunc.Debugf("checking if CA '%s' exists", input.SubjectKeyID)
	exists, ca, err := svc.certStorage.SelectExistsCAByID(ctx, input.SubjectKeyID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA '%s' exists in storage engine: %s", input.SubjectKeyID, err)
		return false, err
	}

	if !exists {
		lFunc.Errorf("CA %s can not be found in storage engine", input.SubjectKeyID)
		return false, errs.ErrCANotFound
	}
	engine := svc.cryptoEngines[ca.EngineID]
	x509Engine := x509engines.NewX509Engine(lFunc, engine, svc.vaServerDomains)
	lFunc.Debugf("verify signature with %s CA and %s crypto engine", input.SubjectKeyID, x509Engine.GetEngineConfig().Provider)
	return x509Engine.Verify(ctx, (*x509.Certificate)(ca.Certificate), input.Signature, input.Message, input.MessageType, input.SigningAlgorithm)
}

// Returned Error Codes:
//   - ErrCertificateNotFound
//     The specified Certificate can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceBackend) GetCertificateBySerialNumber(ctx context.Context, input services.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

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

func (svc *CAServiceBackend) GetCertificates(ctx context.Context, input services.GetCertificatesInput) (string, error) {
	return svc.certStorage.SelectAll(ctx, storage.StorageListRequest[models.Certificate]{
		ExhaustiveRun: input.ExhaustiveRun,
		ApplyFunc:     input.ApplyFunc,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     nil,
	})
}

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceBackend) GetCertificatesByCA(ctx context.Context, input services.GetCertificatesByCAInput) (string, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("GetCertificatesByCAInput struct validation error: %s", err)
		return "", errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if CA '%s' exists", input.SubjectKeyID)
	exists, _, err := svc.certStorage.SelectExistsCAByID(ctx, input.SubjectKeyID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA '%s' exists in storage engine: %s", input.SubjectKeyID, err)
		return "", err
	}

	if !exists {
		lFunc.Errorf("CA %s can not be found in storage engine", input.SubjectKeyID)
		return "", errs.ErrCANotFound
	}

	lFunc.Debugf("reading certificates by %s CA", input.SubjectKeyID)
	return svc.certStorage.SelectByCA(ctx, input.SubjectKeyID, storage.StorageListRequest[models.Certificate]{
		ExhaustiveRun: input.ExhaustiveRun,
		ApplyFunc:     input.ApplyFunc,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     nil,
	})
}

func (svc *CAServiceBackend) GetCertificatesByExpirationDate(ctx context.Context, input services.GetCertificatesByExpirationDateInput) (string, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Debugf("reading certificates by expiration date. expiresafter: %s. expiresbefore: %s", input.ExpiresAfter, input.ExpiresBefore)
	return svc.certStorage.SelectByExpirationDate(ctx, input.ExpiresBefore, input.ExpiresAfter, storage.StorageListRequest[models.Certificate]{
		ExhaustiveRun: input.ExhaustiveRun,
		ApplyFunc:     input.ApplyFunc,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     nil,
	})
}

func (svc *CAServiceBackend) GetCertificatesByCaAndStatus(ctx context.Context, input services.GetCertificatesByCaAndStatusInput) (string, error) {
	return svc.certStorage.SelectByCAIDAndStatus(ctx, input.SubjectKeyID, input.Status, storage.StorageListRequest[models.Certificate]{
		ExhaustiveRun: input.ExhaustiveRun,
		ApplyFunc:     input.ApplyFunc,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     nil,
	})
}

func (svc *CAServiceBackend) GetCertificatesByStatus(ctx context.Context, input services.GetCertificatesByStatusInput) (string, error) {
	return svc.certStorage.SelectByStatus(ctx, input.Status, storage.StorageListRequest[models.Certificate]{
		ExhaustiveRun: input.ExhaustiveRun,
		ApplyFunc:     input.ApplyFunc,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     nil,
	})
}

// Returned Error Codes:
//   - ErrCertificateNotFound
//     The specified Certificate can not be found in the Database
//   - ErrCertificateStatusTransitionNotAllowed
//     The specified status is not valid for this certficate due to its initial status
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceBackend) UpdateCertificateStatus(ctx context.Context, input services.UpdateCertificateStatusInput) (*models.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

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

// Returned Error Codes:
//   - ErrCertificateNotFound
//     The specified Certificate can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceBackend) UpdateCertificateMetadata(ctx context.Context, input services.UpdateCertificateMetadataInput) (*models.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

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

	updatedMetadata, err := chelpers.ApplyPatches(cert.Metadata, input.Patches)
	if err != nil {
		lFunc.Errorf("failed to apply patches to metadata for Certificate '%s': %v", input.SerialNumber, err)
		return nil, err
	}

	cert.Metadata = updatedMetadata

	lFunc.Debugf("updating %s certificate metadata", input.SerialNumber)
	return svc.certStorage.Update(ctx, cert)
}

func createCAValidation(sl validator.StructLevel) {
	ca := sl.Current().Interface().(services.CreateCAInput)
	if !helpers.ValidateValidity(ca.CAExpiration) {
		// lFunc.Errorf("CA Expiration time ref is incompatible with the selected variable")
		sl.ReportError(ca.CAExpiration, "CAExpiration", "CAExpiration", "InvalidCAExpiration", "")
	}
}

func importCertificateValidation(sl validator.StructLevel) {
	ca := sl.Current().Interface().(services.ImportCertificateInput)
	caCert := ca.Certificate

	if ca.PrivateKey != nil {
		valid, err := chelpers.ValidateCertAndPrivKey((*x509.Certificate)(caCert), ca.PrivateKey)
		if err != nil {
			sl.ReportError(ca.PrivateKey, "PrivateKey", "PrivateKey", "PrivateKeyAndCertificateNotMatch", "")
		}

		if !valid {
			// lFunc.Errorf("CA certificate and the private key provided are not compatible")
			sl.ReportError(ca.PrivateKey, "PrivateKey", "PrivateKey", "PrivateKeyAndCertificateNotMatch", "")
		}
	}
}
