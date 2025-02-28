package services

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/x509engines"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"

	"golang.org/x/crypto/ocsp"
)

type CAMiddleware func(services.CAService) services.CAService

var validate *validator.Validate

type CAServiceBackend struct {
	kmsService                  services.AsymmetricKMSService
	service                     services.CAService
	caStorage                   storage.CACertificatesRepo
	certStorage                 storage.CertificatesRepo
	caCertificateRequestStorage storage.CACertificateRequestRepo
	cryptoMonitorConfig         cconfig.MonitoringJob
	vaServerDomains             []string
	logger                      *logrus.Entry
	x509Engine                  x509engines.X509Engine
}

type CAServiceBuilder struct {
	Logger                      *logrus.Entry
	CAStorage                   storage.CACertificatesRepo
	CertificateStorage          storage.CertificatesRepo
	CACertificateRequestStorage storage.CACertificateRequestRepo
	CryptoMonitoringConf        cconfig.MonitoringJob
	VAServerDomains             []string
}

func NewCAService(builder CAServiceBuilder) (services.CAService, error) {
	validate = validator.New()

	svc := CAServiceBackend{
		caStorage:                   builder.CAStorage,
		certStorage:                 builder.CertificateStorage,
		caCertificateRequestStorage: builder.CACertificateRequestStorage,
		cryptoMonitorConfig:         builder.CryptoMonitoringConf,
		vaServerDomains:             builder.VAServerDomains,
		logger:                      builder.Logger,
		x509Engine:                  x509engines.NewX509Engine(builder.Logger, builder.VAServerDomains),
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
			TotalCAs:  totalCAs,
			CAsStatus: casStatus,
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

func (svc *CAServiceBackend) ImportCA(ctx context.Context, input services.ImportCAInput) (*models.CACertificate, error) {
	return nil, nil
}
func (svc *CAServiceBackend) CreateCA(ctx context.Context, input services.CreateCAInput) (*models.CACertificate, error) {
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

	// Check if CA already exists
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
			ID:    caID,
			Level: 0,
		}
	} else {
		// Subordinate CA. Before creating a subordinate CA, it is required to check if the parent CA exists
		exists, parentCA, err := svc.caStorage.SelectExistsByID(ctx, input.ParentID)
		if err != nil {
			lFunc.Errorf("could not check if parent CA %s exists: %s", input.ParentID, err)
			return nil, err
		}

		if !exists {
			lFunc.Errorf("parent CA %s does not exist", input.ParentID)
			return nil, errs.ErrCANotFound
		}

		var caExpiration time.Time
		if input.IssuanceExpiration.Type == models.Duration {
			caExpiration = time.Now().Add((time.Duration)(input.CAExpiration.Duration))
		} else {
			caExpiration = input.CAExpiration.Time
		}

		parentCaExpiration := parentCA.Certificate.ValidTo
		if parentCaExpiration.Before(caExpiration) {
			lFunc.Errorf("requested CA would expire after parent CA")
			return nil, fmt.Errorf("invalid expiration")
		}

		lFunc.Debugf("valid expiration. Subordinated CA expires before parent CA")

		// Generate a new Key Pair and a CSR for the CA
		caCSR, err := svc.RequestCACSR(ctx, services.RequestCAInput{
			ID:          input.ID,
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
			CAID:            input.ParentID,
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
			SN:    parentCA.Certificate.SerialNumber,
			ID:    parentCA.ID,
			Level: parentCA.Level,
		}
	}

	if err != nil {
		lFunc.Errorf("could not create CA %s certificate: %s", input.Subject.CommonName, err)
		return nil, err
	}

	caCert := models.CACertificate{
		ID:         caID,
		Metadata:   input.Metadata,
		Validity:   input.IssuanceExpiration,
		CreationTS: time.Now(),
		Level:      caLevel,
		Certificate: models.Certificate{
			KeyID:        keyID,
			Certificate:  (*models.X509Certificate)(ca),
			Status:       models.StatusActive,
			SerialNumber: helpers.SerialNumberToString(ca.SerialNumber),
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
			Metadata:            map[string]interface{}{},
			Type:                models.CertificateTypeManaged,
			EngineID:            engineID,
			IsCA:                true,
		},
	}

	lFunc.Debugf("insert CA %s in storage engine", caID)
	return svc.caStorage.Insert(ctx, &caCert)
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
func (svc *CAServiceBackend) GetCAByID(ctx context.Context, input services.GetCAByIDInput) (*models.CACertificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := validate.Struct(input)
	if err != nil {
		lFunc.Errorf("GetByIDInput struct validation error: %s", err)
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

func (svc *CAServiceBackend) GetCAs(ctx context.Context, input services.GetCAsInput) (string, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

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

func (svc *CAServiceBackend) GetCABySerialNumber(ctx context.Context, input services.GetCABySerialNumberInput) (*models.CACertificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

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

func (svc *CAServiceBackend) GetCAsByCommonName(ctx context.Context, input services.GetCAsByCommonNameInput) (string, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

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

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
//   - ErrCAAlreadyRevoked
//     CA already revoked
func (svc *CAServiceBackend) UpdateCAStatus(ctx context.Context, input services.UpdateCAStatusInput) (*models.CACertificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

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

	if ca.Certificate.Status == models.StatusExpired {
		lFunc.Errorf("cannot update an expired CA certificate")
		return nil, errs.ErrCertificateStatusTransitionNotAllowed
	}

	if ca.Certificate.Status == models.StatusRevoked && ca.Certificate.RevocationReason != ocsp.CertificateHold {
		lFunc.Errorf("cannot update a revoke CA certificate in %s status. Only a revoked CA certificate with reason '6 - CertificateHold' can be unrevoked", ca.Certificate.RevocationReason.String())
		return nil, errs.ErrCertificateStatusTransitionNotAllowed
	}

	ca.Certificate.Status = input.Status
	if ca.Certificate.Status == models.StatusRevoked {
		rrb, _ := input.RevocationReason.MarshalText()
		lFunc.Infof("CA %s is being revoked with revocation reason %d - %s", input.CAID, input.RevocationReason, string(rrb))
		ca.Certificate.RevocationReason = input.RevocationReason
		ca.Certificate.RevocationTimestamp = time.Now()
	}

	lFunc.Debugf("updating the status of CA %s to %s", input.CAID, input.Status)
	ca, err = svc.caStorage.Update(ctx, ca)
	if err != nil {
		lFunc.Errorf("could not update CA %s status: %s", input.CAID, err)
		return nil, err
	}

	if input.Status == models.StatusRevoked {
		revokeCAFunc := func(ca models.CACertificate) {
			_, err := svc.service.UpdateCAStatus(ctx, services.UpdateCAStatusInput{
				CAID:             ca.ID,
				Status:           models.StatusRevoked,
				RevocationReason: ocsp.CessationOfOperation,
			})
			if err != nil {
				lFunc.Errorf("could not revoke child CA Certificate %s issued by CA %s", ca.ID, ca.Certificate.IssuerCAMetadata.ID)
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
			_, err := svc.service.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
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

func (svc *CAServiceBackend) UpdateCAIssuanceExpiration(ctx context.Context, input services.UpdateCAIssuanceExpirationInput) (*models.CACertificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)
	var err error
	err = validate.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateIssuanceExpirationInput struct validation error: %s", err)
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

	if !helpers.ValidateCAExpiration(input.IssuanceExpiration, ca.Certificate.ValidTo) {
		lFunc.Errorf("issuance expiration is greater than the CA expiration")
		return nil, errs.ErrValidateBadRequest
	}

	ca.Validity = input.IssuanceExpiration

	lFunc.Debugf("updating %s CA issuance expiration", input.CAID)
	return svc.caStorage.Update(ctx, ca)

}

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceBackend) UpdateCAMetadata(ctx context.Context, input services.UpdateCAMetadataInput) (*models.CACertificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

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

	if ca.Certificate.Type == models.CertificateTypeExternal {
		lFunc.Debugf("External CA can be deleted. Proceeding")
	} else if ca.Certificate.Status == models.StatusExpired || ca.Certificate.Status == models.StatusRevoked {
		lFunc.Debugf("Expired or revoked CA can be deleted. Proceeding")
	} else {
		lFunc.Errorf("CA %s can not be deleted while in status %s", input.CAID, ca.Certificate.Status)
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
	_, err = svc.certStorage.SelectByCA(ctx, ca.ID, storage.StorageListRequest[models.Certificate]{
		ExhaustiveRun: true,
		ApplyFunc:     revokeCertFunc,
		QueryParams:   &resources.QueryParameters{},
		ExtraOpts:     map[string]interface{}{},
	})
	if err != nil {
		lFunc.Errorf("could not revoke certificate %s issued by CA %s", ca.Certificate.SerialNumber, ca.Certificate.IssuerCAMetadata.ID)
	}
	err = svc.caStorage.Delete(ctx, input.CAID)
	if err != nil {
		lFunc.Errorf("something went wrong while deleting the CA %s %s", input.CAID, err)
		return err
	}

	return err
}

func (svc *CAServiceBackend) SignCertificate(ctx context.Context, input services.SignCertificateInput) (*models.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)
	lFunc.WithField("method", "SignCertificate")

	lFunc.Infof("signing certificate with CA %s", input.CAID)

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

	if ca.Certificate.Status != models.StatusActive {
		lFunc.Errorf("%s CA is not active", ca.ID)
		return nil, errs.ErrCAStatus
	}

	caKp, err := svc.kmsService.GetKeyPair(ctx, services.GetKeyPairInput{
		KeyID: ca.Certificate.KeyID,
	})
	if err != nil {
		lFunc.Errorf("could not get CA %s key pair: %s", ca.ID, err)
		return nil, err
	}

	caSigner := services.NewKeyPairCryptoSigner(ctx, *caKp, svc.kmsService)

	caCert := (*x509.Certificate)(ca.Certificate.Certificate)
	csr := (*x509.CertificateRequest)(input.CertRequest)

	x509Cert, err := svc.x509Engine.SignCertificateRequest(ctx, csr, caCert, caSigner, input.IssuanceProfile)
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
			ID: ca.ID,
		},
		Status: models.StatusActive,
		KeyMetadata: models.KeyStrengthMetadata{
			Type:     models.KeyType(caKp.Algorithm),
			Bits:     caKp.KeySize,
			Strength: models.KeyStrengthHigh,
		},
		Subject:             chelpers.PkixNameToSubject(x509Cert.Subject),
		SerialNumber:        helpers.SerialNumberToString(x509Cert.SerialNumber),
		ValidFrom:           x509Cert.NotBefore,
		ValidTo:             x509Cert.NotAfter,
		RevocationTimestamp: time.Time{},
		IsCA:                x509Cert.IsCA,
		KeyID:               "",
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

func (svc *CAServiceBackend) ImportCertificate(ctx context.Context, input services.ImportCertificateInput) (*models.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	x509Cert := (*x509.Certificate)(input.Certificate)
	var err error
	var kp *models.KeyPair

	if input.PrivateKey != nil {
		kp, err = svc.kmsService.ImportKeyPair(ctx, services.ImportKeyPairInput{
			EngineID:   input.EngineID,
			PrivateKey: *input.PrivateKey,
		})

	} else {
		pubkey := input.Certificate.PublicKey

		kp, err = svc.kmsService.ImportKeyPair(ctx, services.ImportKeyPairInput{
			PublicKey: models.X509PublicKey{Key: pubkey},
		})
	}

	if err != nil {
		return nil, fmt.Errorf("could not import key: %w", err)
	}

	status := models.StatusActive
	if input.Certificate.NotAfter.Before(time.Now()) {
		status = models.StatusExpired
	}

	newCert := models.Certificate{
		Metadata:    input.Metadata,
		Type:        models.CertificateTypeExternal,
		Certificate: (*models.X509Certificate)(input.Certificate),
		Status:      status,
		KeyMetadata: models.KeyStrengthMetadata{
			Type:     models.KeyType(kp.Algorithm),
			Bits:     kp.KeySize,
			Strength: kp.KeyStrength,
		},
		Subject:             chelpers.PkixNameToSubject(input.Certificate.Subject),
		SerialNumber:        helpers.SerialNumberToString(input.Certificate.SerialNumber),
		ValidFrom:           input.Certificate.NotBefore,
		ValidTo:             input.Certificate.NotAfter,
		RevocationTimestamp: time.Time{},
		IsCA:                x509Cert.IsCA,
	}

	if x509Cert.IsCA {
		// Also insert into CAs DB
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
			SN:    parentCA.Certificate.SerialNumber,
			ID:    parentCA.ID,
			Level: parentCA.Level,
		}
	} else {
		newCert.IssuerCAMetadata = models.IssuerCAMetadata{
			SN:    "-",
			ID:    "-",
			Level: -1,
		}
	}

	cert, err := svc.certStorage.Insert(ctx, &newCert)
	if err != nil {
		lFunc.Errorf("could not insert certificate: %s", err)
		return nil, err
	}

	return cert, nil
}

func (svc *CAServiceBackend) SignatureSign(ctx context.Context, input services.SignatureSignInput) ([]byte, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

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

	engine := svc.cryptoEngines[ca.Certificate.EngineID]
	x509Engine := x509engines.NewX509Engine(lFunc, engine, svc.vaServerDomains)
	lFunc.Debugf("sign signature with %s CA and %s crypto engine", input.CAID, x509Engine.GetEngineConfig().Provider)
	signature, err := x509Engine.Sign(ctx, (*x509.Certificate)(ca.Certificate.Certificate), input.Message, input.MessageType, input.SigningAlgorithm)
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
	engine := svc.cryptoEngines[ca.Certificate.EngineID]
	x509Engine := x509engines.NewX509Engine(lFunc, engine, svc.vaServerDomains)
	lFunc.Debugf("verify signature with %s CA and %s crypto engine", input.CAID, x509Engine.GetEngineConfig().Provider)
	return x509Engine.Verify(ctx, (*x509.Certificate)(ca.Certificate.Certificate), input.Signature, input.Message, input.MessageType, input.SigningAlgorithm)
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
	return svc.certStorage.SelectByCAIDAndStatus(ctx, input.CAID, input.Status, storage.StorageListRequest[models.Certificate]{
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

	cert.Metadata = input.Metadata
	lFunc.Debugf("updating %s certificate metadata", input.SerialNumber)
	return svc.certStorage.Update(ctx, cert)
}

func createCAValidation(sl validator.StructLevel) {
	ca := sl.Current().Interface().(services.CreateCAInput)
	if !helpers.ValidateValidity(ca.CAExpiration) {
		// lFunc.Errorf("CA Expiration time ref is incompatible with the selected variable")
		sl.ReportError(ca.CAExpiration, "CAExpiration", "CAExpiration", "InvalidCAExpiration", "")
	}

	if !helpers.ValidateValidity(ca.IssuanceExpiration) {
		// lFunc.Errorf("issuance expiration time ref is incompatible with the selected variable")
		sl.ReportError(ca.IssuanceExpiration, "IssuanceExpiration", "IssuanceExpiration", "InvalidIssuanceExpiration", "")
	}

	expiration := time.Now()
	if ca.CAExpiration.Type == models.Duration {
		expiration = expiration.Add(time.Duration(ca.CAExpiration.Duration))
	} else {
		expiration = ca.CAExpiration.Time
	}

	if !helpers.ValidateCAExpiration(ca.IssuanceExpiration, expiration) {
		// lFunc.Errorf("issuance expiration is greater than the CA expiration")
		sl.ReportError(ca.IssuanceExpiration, "IssuanceExpiration", "IssuanceExpiration", "IssuanceExpirationGreaterThanCAExpiration", "")
	}
}

func importCAValidation(sl validator.StructLevel) {
	ca := sl.Current().Interface().(services.ImportCAInput)
	caCert := ca.CACertificate

	if ca.CAType == models.CertificateTypeImportedWithKey {
		if !helpers.ValidateCAExpiration(ca.IssuanceExpiration, caCert.NotAfter) {
			// lFunc.Errorf("issuance expiration is greater than the CA expiration")
			sl.ReportError(ca.IssuanceExpiration, "IssuanceExpiration", "IssuanceExpiration", "IssuanceExpirationGreaterThanCAExpiration", "")
		}
		// lFunc.Debugf("CA Type: %s", ca.CAType)
		if !helpers.ValidateValidity(ca.IssuanceExpiration) {
			// lFunc.Errorf("expiration time ref is incompatible with the selected variable")
			sl.ReportError(ca.IssuanceExpiration, "IssuanceExpiration", "IssuanceExpiration", "InvalidIssuanceExpiration", "")
		}

		valid, err := chelpers.ValidateCertAndPrivKey((*x509.Certificate)(caCert), ca.CARSAKey, ca.CAECKey)
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
