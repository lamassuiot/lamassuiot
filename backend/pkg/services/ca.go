package services

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"math/big"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/x509engines"
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

var caValidator *validator.Validate

type CAServiceBackend struct {
	service                 services.CAService
	kmsService              services.KMSService
	caStorage               storage.CACertificatesRepo
	certStorage             storage.CertificatesRepo
	issuanceProfilesStorage storage.IssuanceProfileRepo
	vaServerDomains         []string
	allowCascadeDelete      bool
	logger                  *logrus.Entry
}

type CAServiceBuilder struct {
	Logger                 *logrus.Entry
	CAStorage              storage.CACertificatesRepo
	CertificateStorage     storage.CertificatesRepo
	IssuanceProfileStorage storage.IssuanceProfileRepo
	VAServerDomains        []string
	KMSService             services.KMSService
	AllowCascadeDelete     bool
}

func NewCAService(builder CAServiceBuilder) (services.CAService, error) {
	caValidator = validator.New()

	svc := &CAServiceBackend{
		caStorage:               builder.CAStorage,
		certStorage:             builder.CertificateStorage,
		issuanceProfilesStorage: builder.IssuanceProfileStorage,
		vaServerDomains:         builder.VAServerDomains,
		allowCascadeDelete:      builder.AllowCascadeDelete,
		kmsService:              builder.KMSService,
		logger:                  builder.Logger,
	}

	svc.service = svc

	return svc, nil
}

func (svc *CAServiceBackend) Close() {
	//no op
}

func (svc *CAServiceBackend) SetService(service services.CAService) {
	svc.service = service
}

func (svc *CAServiceBackend) GetStats(ctx context.Context) (*models.CAStats, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

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

func (svc *CAServiceBackend) ImportCA(ctx context.Context, input services.ImportCAInput) (*models.CACertificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)
	var err error

	// Validate IssuanceProfileID exists if provided (required for ImportedWithKey type)
	if input.ProfileID != "" {
		_, err = svc.service.GetIssuanceProfileByID(ctx, services.GetIssuanceProfileByIDInput{
			ProfileID: input.ProfileID,
		})
		if err != nil {
			return nil, err
		}
	}

	caCert := input.CACertificate
	caCertSN := helpers.SerialNumberToHexString(caCert.SerialNumber)

	caCertX509 := (*x509.Certificate)(input.CACertificate)

	skid, err := helpers.GetSubjectKeyID(lFunc, caCertX509)
	if err != nil {
		lFunc.Errorf("could not get Subject Key Identifier for certificate: %s: %s", caCertX509.Subject.CommonName, err)
		return nil, err
	}

	var importType models.CertificateType
	var key *models.Key

	if input.Key != nil {
		importType = models.CertificateTypeImportedWithKey
		lFunc.Debugf("importing CA %s - %s  private key. CA type: %s", caCertSN, caCert.Subject.CommonName, importType)

		key, err = svc.kmsService.ImportKey(ctx, services.ImportKeyInput{
			PrivateKey: input.Key,
		})
		if err != nil {
			lFunc.Errorf("could not import CA %s private key: %s", caCertSN, err)
			return nil, fmt.Errorf("could not import key: %w", err)
		}

		if key.KeyID != skid {
			key, err = svc.kmsService.UpdateKeyMetadata(ctx, services.UpdateKeyMetadataInput{
				ID: key.KeyID,
				Patches: chelpers.NewPatchBuilder().Add(chelpers.JSONPointerBuilder(models.KMSBindResourceKey, "-"), models.KMSBindResource{
					ResourceType: "certificate",
					ResourceID:   helpers.SerialNumberToHexString(caCert.SerialNumber),
				}).Build(),
			})
			if err != nil {
				lFunc.Errorf("could not rename imported key to match SKID %s: %s", skid, err)
				return nil, fmt.Errorf("could not rename imported key: %w", err)
			}
		}

		if err != nil {
			lFunc.Errorf("could not import CA %s private key: %s", caCertSN, err)
			return nil, fmt.Errorf("could not import key: %w", err)
		}
	} else {
		//search in KMS if key exists for the CA being imported
		key, err = svc.kmsService.GetKey(ctx, services.GetKeyInput{
			Identifier: skid,
		})
		if err != nil {
			lFunc.Infof("could not find key with SKID %s for CA %s: %s. Assuming key does not exist", skid, caCertSN, err)
			importType = models.CertificateTypeImportedWithoutKey
		} else {
			lFunc.Infof("found key with SKID %s for CA %s in KMS", skid, caCertSN)
			importType = models.CertificateTypeManaged
		}
	}

	caID := input.ID
	if caID == "" {
		caID = goid.NewV4UUID().String()
	}

	issuerMeta := models.IssuerCAMetadata{
		ID:    caID,
		SN:    caCertSN,
		Level: 0,
	}
	level := 0

	akid := hex.EncodeToString(caCertX509.AuthorityKeyId)

	isSelfSigned := false
	if err := caCertX509.CheckSignatureFrom(caCertX509); err != nil {
		isSelfSigned = false
	} else {
		isSelfSigned = true
	}

	if !isSelfSigned {
		var candidateParentCAs []models.CACertificate

		findParentCAInArray := func(ca *models.X509Certificate, parentCAs []models.CACertificate) *models.CACertificate {
			// Iterate over candidate parent CAs to verify and assign values when found
			for _, parentCA := range parentCAs {
				p := x509.Certificate(*parentCA.Certificate.Certificate)
				c := x509.Certificate(*ca)
				err = c.CheckSignatureFrom(&p)

				if err != nil {
					if akid != "" {
						lFunc.Warnf("possible parent CA detected, but failed cryptographic validation: %s", err)
					}
					continue // Skip if verification fails
				}

				// If the signature is valid, return the parent CA
				return &parentCA
			}

			// If no valid parent CA is found, return nil
			return nil
		}

		// 1st Attempt: Check if the CA is signed by a parent CA using Authority Key Identifier (AKID)
		lFunc.Debugf("checking if CA %s is signed by a parent CA using AKID", input.CACertificate.Subject.CommonName)
		svc.caStorage.SelectBySubjectAndSubjectKeyID(ctx, chelpers.PkixNameToSubject(input.CACertificate.Issuer), akid,
			storage.StorageListRequest[models.CACertificate]{
				ExhaustiveRun: true,
				ApplyFunc: func(c models.CACertificate) {
					candidateParentCAs = append(candidateParentCAs, c)
				},
			})

		parentCA := findParentCAInArray(input.CACertificate, candidateParentCAs)
		if parentCA != nil {
			lFunc.Debugf("found parent CA %s with AKID %s", parentCA.ID, parentCA.Certificate.AuthorityKeyID)
			akid = parentCA.Certificate.AuthorityKeyID
			// When verification is successful, update the level and metadata
			level = parentCA.Level + 1
			issuerMeta = models.IssuerCAMetadata{
				ID:    parentCA.ID,
				SN:    parentCA.Certificate.SerialNumber,
				Level: parentCA.Level,
			}
		} else {
			lFunc.Warnf("no parent CA found with AKID %s. Will attempt to find by Issuer Subject", akid)

			// 2nd Attempt: Find all CAs based on the Issuer Subject of the certificate being imported
			candidateParentCAs = []models.CACertificate{}
			svc.caStorage.SelectAll(ctx, storage.StorageListRequest[models.CACertificate]{
				ExhaustiveRun: true,
				ApplyFunc: func(c models.CACertificate) {
					if chelpers.PkixNameEqual(c.Certificate.Certificate.Subject, input.CACertificate.Issuer) {
						candidateParentCAs = append(candidateParentCAs, c)
					}
				},
			})

			parentCA = findParentCAInArray(input.CACertificate, candidateParentCAs)
			if parentCA != nil {
				lFunc.Debugf("found parent CA %s with AKID %s", parentCA.ID, parentCA.Certificate.AuthorityKeyID)
				akid = parentCA.Certificate.AuthorityKeyID
				// When verification is successful, update the level and metadata
				level = parentCA.Level + 1
				issuerMeta = models.IssuerCAMetadata{
					ID:    parentCA.ID,
					SN:    parentCA.Certificate.SerialNumber,
					Level: parentCA.Level,
				}
			} else {
				lFunc.Warnf("no parent CA found with Issuer Subject %s in PKI.", input.CACertificate.Issuer.CommonName)
				issuerMeta = models.IssuerCAMetadata{
					ID:    "-",
					SN:    caCertSN,
					Level: -1,
				}
			}
		}

	} else {
		// Verify that the parent CA is in fact the CA that signed the certificate, which is the same as the CA being imported when self-signed
		p := x509.Certificate(*caCert)
		c := x509.Certificate(*caCert)
		err = c.CheckSignatureFrom(&p)
		if err != nil {
			lFunc.Errorf("parent CA did not sign the certificate: %s", err)
			return nil, fmt.Errorf("parent CA did not sign the certificate: %w", err)
		}
	}

	engineID := ""
	if key != nil {
		engineID = key.EngineID
		key, err = svc.kmsService.UpdateKeyMetadata(ctx, services.UpdateKeyMetadataInput{
			ID: key.KeyID,
			Patches: chelpers.NewPatchBuilder().Add(chelpers.JSONPointerBuilder(models.KMSBindResourceKey, "-"), models.KMSBindResource{
				ResourceType: "certificate",
				ResourceID:   helpers.SerialNumberToHexString(caCert.SerialNumber),
			}).Build(),
		})
		if err != nil {
			lFunc.Errorf("could not bind CA %s to key %s: %s", caCert.Subject.CommonName, key.KeyID, err)
			return nil, err
		}
	}

	ca := &models.CACertificate{
		ID:         caID,
		Metadata:   map[string]interface{}{},
		ProfileID:  input.ProfileID,
		CreationTS: time.Now(),
		Level:      level,
		Certificate: models.Certificate{
			VersionSchema:       "unknown",
			SubjectKeyID:        skid,
			AuthorityKeyID:      akid,
			Certificate:         input.CACertificate,
			Status:              models.StatusActive,
			SerialNumber:        helpers.SerialNumberToHexString(caCert.SerialNumber),
			KeyMetadata:         helpers.KeyStrengthMetadataFromCertificate((*x509.Certificate)(caCert)),
			Subject:             chelpers.PkixNameToSubject(caCert.Subject),
			Issuer:              chelpers.PkixNameToSubject(caCert.Issuer),
			ValidFrom:           caCert.NotBefore,
			ValidTo:             caCert.NotAfter,
			RevocationTimestamp: time.Time{},
			Metadata:            map[string]interface{}{},
			Type:                importType,
			IssuerCAMetadata:    issuerMeta,
			EngineID:            engineID,
			IsCA:                true,
		},
	}

	lFunc.Debugf("insert CA %s in storage engine", caID)
	cert, err := svc.caStorage.Insert(ctx, ca)

	// Flag to check if it's the first iteration
	firstIteration := true
	queue := []models.CACertificate{*ca}

	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:] // Dequeue

		// In the future if we plan to support Cross Signed certs, it is important not fetching just by AKI,
		// since two cross signed certs (using the same SKI) are signed by different AKIs. Hence, we select by AKI AND Issuer DSN
		svc.caStorage.SelectByIssuerAndAuthorityKeyID(ctx, parent.Certificate.Subject, parent.Certificate.SubjectKeyID, storage.StorageListRequest[models.CACertificate]{
			ExhaustiveRun: true,
			ApplyFunc: func(child models.CACertificate) {
				childCertX509 := (*x509.Certificate)(child.Certificate.Certificate)
				isSelfSignedChild := false
				if err := childCertX509.CheckSignatureFrom(childCertX509); err != nil {
					isSelfSignedChild = false
				} else {
					isSelfSignedChild = true
				}

				if !isSelfSignedChild {
					if firstIteration { //Check also with crypto validation to ensure child is actually signed by parent?
						p := x509.Certificate(*parent.Certificate.Certificate)
						c := x509.Certificate(*child.Certificate.Certificate)
						err = c.CheckSignatureFrom(&p)

						if err != nil {
							if child.Certificate.AuthorityKeyID != "" {
								lFunc.Warnf("possible child CA detected, but failed cryptographic validation: %s", err)
							}
							return // if verification fails, "tentative" parent CA did not sign the certificate being imported. skip update
						}
					}

					// We are certain the parent CA did sign the certificate being imported
					child.Level = parent.Level + 1
					child.Certificate.IssuerCAMetadata.ID = parent.ID
					child.Certificate.IssuerCAMetadata.Level = parent.Level
					child.Certificate.IssuerCAMetadata.SN = parent.Certificate.SerialNumber

					// Update the level in DB
					svc.caStorage.Update(ctx, &child)

					// Enqueue child for further processing
					queue = append(queue, child)
				}
			},
		})
		firstIteration = false
	}

	return cert, err
}

func (svc *CAServiceBackend) CreateCA(ctx context.Context, input services.CreateCAInput) (*models.CACertificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	caID, err := svc.validateCreateCAInput(ctx, &input)
	if err != nil {
		return nil, err
	}
	
	lFunc.Debugf("creating CA with common name: %s", input.Subject.CommonName)

	var ca *x509.Certificate
	var caLevel int
	var issuerCAMeta models.IssuerCAMetadata

	key, err := svc.getOrCreateKey(ctx, &input.KeyMetadata, input.EngineID, input.Subject.CommonName)
	if err != nil {
		return nil, err
	}

	signer := NewKMSCryptoSigner(ctx, *key, svc.kmsService)
	engine := x509engines.NewX509Engine(lFunc, svc.vaServerDomains, svc.kmsService)

	var akid, skid string
	skid = key.KeyID
	// Check if CA is Root (self-signed) or Subordinate (signed by another CA). Non self-signed/root CAs require a parent CA
	if input.ParentID == "" {
		// Generate Key Pair to be used by the new CA
		akid = key.KeyID

		// Root CA. Root CAs can be generate directly
		ca, err = engine.CreateRootCA(ctx, signer, key.KeyID, input.Subject, input.CAExpiration)
		if err != nil {
			lFunc.Errorf("could not create CA %s certificate: %s", input.Subject.CommonName, err)
			return nil, err
		}

		caLevel = 0
		issuerCAMeta = models.IssuerCAMetadata{
			SN:    helpers.SerialNumberToHexString(ca.SerialNumber),
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

		akid = parentCA.Certificate.SubjectKeyID

		// Generate a new Key Pair and a CSR for the CA
		template := svc.createCSRTemplate(ctx, &input)
		csrDerBytes, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
		if err != nil {
			lFunc.Errorf("could not create CSR for CA %s: %s", input.Subject.CommonName, err)
			return nil, err
		}

		csr, _ := x509.ParseCertificateRequest(csrDerBytes)
		issuanceProfile := engine.GetDefaultCAIssuanceProfile(ctx, input.CAExpiration)

		signedCA, err := svc.SignCertificate(ctx, services.SignCertificateInput{
			CAID:            input.ParentID,
			CertRequest:     (*models.X509CertificateRequest)(csr),
			IssuanceProfile: &issuanceProfile,
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

	key, err = svc.updateCAKeyMetadata(ctx, key, ca.SerialNumber)
	if err != nil {
		lFunc.Errorf("could not bind CA %s to key %s: %s", input.Subject.CommonName, key.KeyID, err)
		return nil, err
	}

	caCert := models.CACertificate{
		ID:         caID,
		Metadata:   input.Metadata,
		ProfileID:  input.ProfileID,
		CreationTS: time.Now(),
		Level:      caLevel,
		Certificate: models.Certificate{
			VersionSchema:  "1.0",
			SubjectKeyID:   skid,
			AuthorityKeyID: akid,
			Certificate:    (*models.X509Certificate)(ca),
			Status:         models.StatusActive,
			SerialNumber:   helpers.SerialNumberToHexString(ca.SerialNumber),
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
			EngineID:            key.EngineID,
			IsCA:                true,
		},
	}

	lFunc.Debugf("insert CA %s in storage engine", caID)
	return svc.caStorage.Insert(ctx, &caCert)
}

// TODO --> Add Bound Certificate Support
func (svc *CAServiceBackend) CreateHybridCA(ctx context.Context, input services.CreateHybridCAInput) (*models.CACertificate, error) {
	var caCertificate *models.CACertificate
	var err error

	switch input.HybridCertificateType {
	case models.HybridCertificateTypeChameleon:
		caCertificate, err = svc.createChameleonCA(ctx, input)
	default:
		err = fmt.Errorf("Unknown Hybrid CA type: %v", input.HybridCertificateType)
	}

	return caCertificate, err
}

func (svc *CAServiceBackend) createChameleonCA(ctx context.Context, input services.CreateHybridCAInput) (*models.CACertificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	caID, err := svc.validateCreateCAInput(ctx, &input.CreateCAInput)
	if err != nil {
		return nil, err
	}

	baseKey, err := svc.getOrCreateKey(ctx, &input.CreateCAInput.KeyMetadata, input.CreateCAInput.EngineID, input.CreateCAInput.Subject.CommonName)
	if err != nil {
		return nil, err
	}

	deltaKey, err := svc.getOrCreateKey(ctx, &input.InnerKeyMetadata, input.CreateCAInput.EngineID, input.CreateCAInput.Subject.CommonName)
	if err != nil {
		return nil, err
	}

	baseSigner := NewKMSCryptoSigner(ctx, *baseKey, svc.kmsService)
	deltaSigner := NewKMSCryptoSigner(ctx, *deltaKey, svc.kmsService)
	engine := x509engines.NewX509Engine(lFunc, svc.vaServerDomains, svc.kmsService)

	var ca *x509.Certificate
	var caLevel int
	var issuerCAMeta models.IssuerCAMetadata

	var baseAkid, baseSkid string
	var deltaAkid, deltaSkid string
	// Check if CA is Root (self-signed) or Subordinate (signed by another CA). Non self-signed/root CAs require a parent CA
	if input.CreateCAInput.ParentID == "" {
		deltaSkid = deltaKey.KeyID
		deltaAkid = deltaKey.KeyID
		baseSkid = baseKey.KeyID
		baseAkid = baseKey.KeyID

		// Root CA. Root CAs can be generate directly
		ca, err = engine.CreateChameleonRootCA(ctx, deltaSigner, baseSigner, deltaKey.KeyID, baseKey.KeyID, input.CreateCAInput.Subject, input.CreateCAInput.CAExpiration)

		caLevel = 0
		issuerCAMeta = models.IssuerCAMetadata{
			SN:    helpers.SerialNumberToHexString(ca.SerialNumber),
			ID:    caID,
			Level: 0,
		}
	} else {
		// Subordinate CA. Before creating a subordinate CA, it is required to check if the parent CA exists
		exists, baseParentCA, err := svc.caStorage.SelectExistsByID(ctx, input.CreateCAInput.ParentID)
		if err != nil {
			lFunc.Errorf("could not check if parent CA %s exists: %s", input.CreateCAInput.ParentID, err)
			return nil, err
		}
		if !exists {
			lFunc.Errorf("parent CA %s does not exist", input.CreateCAInput.ParentID)
			return nil, errs.ErrCANotFound
		}

		baseAkid = baseParentCA.Certificate.SubjectKeyID
		deltaAkid = baseParentCA.Metadata["lamassu.io/certificate/chameleon"].(map[string]any)["delta"].(map[string]any)["skid"].(string)
		baseSkid = baseKey.KeyID
		deltaSkid = deltaKey.KeyID

		// Generate a new KeyPair and CSR for the delta Certificate
		// NOTE -> maybe both Inner and Outer CA should have the same Id
		template := svc.createCSRTemplate(ctx, &input.CreateCAInput)
		csrBytes, err := x509.CreateChameleonCertificateRequest(rand.Reader, template, template, deltaSigner, baseSigner)
		if err != nil {
			lFunc.Errorf("could not create Chameleon CSR for %s: %s", input.CreateCAInput.Subject.CommonName, err)
			return nil, err
		}
		
		deltaCSR, baseCSR, err := x509.ParseChameleonCertificateRequest(csrBytes)

		// Sign the certificate request
		signedCA, err := svc.SignChameleonCertificate(ctx, services.SignChameleonCertificateInput{
			CAID:             input.CreateCAInput.ParentID,
			BaseCertRequest:  (*models.X509CertificateRequest)(baseCSR),
			DeltaCertRequest: (*models.X509CertificateRequest)(deltaCSR),
			IssuanceProfile:  engine.GetDefaultCAIssuanceProfile(ctx, input.CreateCAInput.CAExpiration),
		})
		if err != nil {
			lFunc.Errorf("could not sign CA %s certificate: %s", input.CreateCAInput.Subject.CommonName, err)
			return nil, err
		}

		ca = (*x509.Certificate)(signedCA.Certificate)

		// Update the CA level and issuer metadata
		caLevel = baseParentCA.Level + 1
		issuerCAMeta = models.IssuerCAMetadata{
			SN:    baseParentCA.Certificate.SerialNumber,
			ID:    baseParentCA.ID,
			Level: baseParentCA.Level,
		}
	}

	if err != nil {
		lFunc.Errorf("could not create CA %s certificate: %s", input.CreateCAInput.Subject.CommonName, err)
		return nil, err
	}

	// Add deltaAkid and Skid as metadata to the certificate
	// TODO -> revisit key names
	input.CreateCAInput.Metadata["lamassu.io/certificate/chameleon"] = map[string]map[string]string {
		"base": {
			"akid": baseAkid,
			"skid": baseSkid,
			"keyinfo": ca.PublicKeyAlgorithm.String(),
		},
		"delta": {
			"akid": deltaAkid,
			"skid": deltaSkid,
			"keyinfo": input.InnerKeyMetadata.Type.String(),
		},
	}

	// Update baseKey metadata
	baseKey, err = svc.updateCAKeyMetadata(ctx, baseKey, ca.SerialNumber)
	if err != nil {
		lFunc.Errorf("could not bind CA %s to key %s: %s", input.CreateCAInput.Subject.CommonName, baseKey.KeyID, err)
		return nil, err
	}

	// Update deltaKey metadata
	deltaCa, err := x509.ReconstructDeltaCertificate(ca)
	if err != nil {
		lFunc.Errorf("could not parse the delta CA certificate for %s: %s", input.CreateCAInput.Subject.CommonName, err)
		return nil, err
	}

	deltaKey, err = svc.updateCAKeyMetadata(ctx, deltaKey, deltaCa.SerialNumber)
	if err != nil {
		lFunc.Errorf("could not bind CA %s to key %s: %s", input.CreateCAInput.Subject.CommonName, deltaKey.KeyID, err)
		return nil, err
	}

	caCert := models.CACertificate{
		ID:         caID,
		Metadata:   input.CreateCAInput.Metadata,
		ProfileID:  input.CreateCAInput.ProfileID,
		CreationTS: time.Now(),
		Level:      caLevel,
		Certificate: models.Certificate{
			VersionSchema:  "1.0",
			SubjectKeyID:   baseSkid,
			AuthorityKeyID: baseAkid,
			Certificate:    (*models.X509Certificate)(ca),
			Status:         models.StatusActive,
			SerialNumber:   helpers.SerialNumberToHexString(ca.SerialNumber),
			KeyMetadata: models.KeyStrengthMetadata{
				Type:     input.CreateCAInput.KeyMetadata.Type,
				Bits:     input.CreateCAInput.KeyMetadata.Bits,
				Strength: models.KeyStrengthHigh,
			},
			Subject:             input.CreateCAInput.Subject,
			ValidFrom:           ca.NotBefore,
			ValidTo:             ca.NotAfter,
			RevocationTimestamp: time.Time{},
			IssuerCAMetadata:    issuerCAMeta,
			Metadata:            map[string]interface{}{},
			Type:                models.CertificateTypeManaged,
			EngineID:            input.CreateCAInput.EngineID,
			IsCA:                true,
		},
	}
	
	lFunc.Debugf("insert CA %s in storage engine", caID)
	return svc.caStorage.Insert(ctx, &caCert)
}

func (svc *CAServiceBackend) validateCreateCAInput(ctx context.Context, input *services.CreateCAInput) (string, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)
	if input.Metadata == nil {
		input.Metadata = map[string]any{}
	}

	var err error
	caValidator.RegisterStructValidation(createCAValidation, services.CreateHybridCAInput{})
	err = caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("CreateCAInput struct validation error: %s", err)
		return "", errs.ErrValidateBadRequest
	}

	// Validate IssuanceProfileID exists
	_, err = svc.service.GetIssuanceProfileByID(ctx, services.GetIssuanceProfileByIDInput{
		ProfileID: input.ProfileID,
	})
	if err != nil {
		return "", err
	}

	// Check if CA already exists
	caID := input.ID
	if caID == "" {
		caID = goid.NewV4UUID().String()
	}

	exists, _, err := svc.caStorage.SelectExistsByID(ctx, caID)
	if err != nil {
		lFunc.Errorf("could not check if CA %s exists: %s", caID, err)
		return "", err
	}

	if exists {
		lFunc.Errorf("cannot create duplicate CA. CA with ID '%s' already exists:", caID)
		return "", errs.ErrCAAlreadyExists
	}

	lFunc.Debugf("creating CA with common name: %s", input.Subject.CommonName)

	return caID, nil
}

func (svc *CAServiceBackend) getOrCreateKey(ctx context.Context, keyMetadata *models.KeyMetadata, engineID string, name string) (*models.Key, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	var key *models.Key
	var err error

	if keyMetadata.KeyID == "" {
		key, err = svc.kmsService.CreateKey(ctx, services.CreateKeyInput{
			Algorithm: keyMetadata.Type.String(),
			Size:      keyMetadata.Bits,
			EngineID:  engineID,
			Name:      fmt.Sprintf("Key For CA CN=%s", name),
		})
		if err != nil {
			lFunc.Errorf("could not create key for CA %s: %s", name, err)
			return nil, err
		}
	} else {
		key, err = svc.kmsService.GetKey(ctx, services.GetKeyInput{
			Identifier: keyMetadata.KeyID,
		})
		if err != nil {
			lFunc.Errorf("could not get key for CA %s: %s", name, err)
			return nil, err
		}
	}

	return key, err
}

func (svc *CAServiceBackend) createCSRTemplate(ctx context.Context, input *services.CreateCAInput) (*x509.CertificateRequest) {
	subject := pkix.Name{
		CommonName: input.Subject.CommonName,
	}

	if input.Subject.Country != "" {
		subject.Country = []string{input.Subject.Country}
	}
	if input.Subject.Organization != "" {
		subject.Organization = []string{input.Subject.Organization}
	}
	if input.Subject.OrganizationUnit != "" {
		subject.OrganizationalUnit = []string{input.Subject.OrganizationUnit}
	}
	if input.Subject.Locality != "" {
		subject.Locality = []string{input.Subject.Locality}
	}
	if input.Subject.State != "" {
		subject.Province = []string{input.Subject.State}
	}

	return &x509.CertificateRequest{
		Subject: subject,
	}
}

func (svc *CAServiceBackend) updateCAKeyMetadata(ctx context.Context, key *models.Key, caSerialNumber *big.Int) (*models.Key, error) {
	key, err := svc.kmsService.UpdateKeyMetadata(ctx, services.UpdateKeyMetadataInput{
		ID: key.KeyID,
		Patches: chelpers.NewPatchBuilder().Add(chelpers.JSONPointerBuilder(models.KMSBindResourceKey, "-"), models.KMSBindResource{
			ResourceType: "certificate",
			ResourceID:   helpers.SerialNumberToHexString(caSerialNumber),
		}).Build(),
	})
	if err != nil {
		return nil, err
	}

	return key, nil
}

// getCACertificateIfExists retrieves the CA certificate for the given caID if it exists.
// Returns the CA certificate and nil error if found, or nil certificate and ErrCANotFound if not found.
func (svc *CAServiceBackend) getCACertificateIfExists(ctx context.Context, caID string) (*models.CACertificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Debugf("checking if CA '%s' exists", caID)
	exists, ca, err := svc.caStorage.SelectExistsByID(ctx, caID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if CA '%s' exists in storage engine: %s", caID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("CA %s can not be found in storage engine", caID)
		return nil, errs.ErrCANotFound
	}

	return ca, nil
}

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceBackend) GetCAByID(ctx context.Context, input services.GetCAByIDInput) (*models.CACertificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("GetByIDInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	ca, err := svc.getCACertificateIfExists(ctx, input.CAID)
	if err != nil {
		return nil, err
	}

	return ca, nil
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

	err := caValidator.Struct(input)
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

	err := caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateCAStatusInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	ca, err := svc.getCACertificateIfExists(ctx, input.CAID)
	if err != nil {
		return nil, err
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

func (svc *CAServiceBackend) UpdateCAProfile(ctx context.Context, input services.UpdateCAProfileInput) (*models.CACertificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateCAProfileInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	ca, err := svc.getCACertificateIfExists(ctx, input.CAID)
	if err != nil {
		return nil, err
	}

	// Validate IssuanceProfileID exists
	_, err = svc.service.GetIssuanceProfileByID(ctx, services.GetIssuanceProfileByIDInput{
		ProfileID: input.ProfileID,
	})
	if err != nil {
		return nil, err
	}

	ca.ProfileID = input.ProfileID

	lFunc.Debugf("updating %s CA profile to %s", input.CAID, input.ProfileID)
	return svc.caStorage.Update(ctx, ca)
}

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceBackend) UpdateCAMetadata(ctx context.Context, input services.UpdateCAMetadataInput) (*models.CACertificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateCAMetadataInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	ca, err := svc.getCACertificateIfExists(ctx, input.CAID)
	if err != nil {
		return nil, err
	}

	updatedMetadata, err := chelpers.ApplyPatches[map[string]any](ca.Metadata, input.Patches)
	if err != nil {
		lFunc.Errorf("failed to apply patches to metadata for CA '%s': %v", input.CAID, err)
		return nil, err
	}

	ca.Metadata = *updatedMetadata

	lFunc.Debugf("updating %s CA metadata", input.CAID)
	return svc.caStorage.Update(ctx, ca)
}

// caValidatorCADeletionEligibility checks if a CA can be deleted based on its type and status
func (svc *CAServiceBackend) caValidatorCADeletionEligibility(ca *models.CACertificate, lFunc *logrus.Entry) error {
	if ca.Certificate.Type == models.CertificateTypeImportedWithoutKey {
		lFunc.Debugf("ImportedWithoutKey CA can be deleted. Proceeding")
		return nil
	}

	if ca.Certificate.Status == models.StatusExpired || ca.Certificate.Status == models.StatusRevoked {
		lFunc.Debugf("Expired or revoked CA can be deleted. Proceeding")
		return nil
	}

	lFunc.Errorf("CA %s can not be deleted while in status %s", ca.ID, ca.Certificate.Status)
	return errs.ErrCAStatus
}

// deleteChildCAs recursively deletes all child CAs issued by the given CA
func (svc *CAServiceBackend) deleteChildCAs(ctx context.Context, ca *models.CACertificate, lFunc *logrus.Entry) error {

	deleteChildCAFunc := func(childCA models.CACertificate) {
		lFunc.Infof("Deleting child CA %s (%s) issued by CA %s", childCA.ID, childCA.Certificate.Subject.CommonName, ca.ID)
		err := svc.service.DeleteCA(ctx, services.DeleteCAInput{
			CAID:          childCA.ID,
			CascadeDelete: true,
		})
		if err != nil {
			lFunc.Errorf("could not delete child CA %s issued by CA %s: %s", childCA.ID, childCA.Certificate.IssuerCAMetadata.ID, err)
		}
	}

	_, err := svc.caStorage.SelectByParentCA(ctx, ca.ID, storage.StorageListRequest[models.CACertificate]{
		ExhaustiveRun: true,
		ApplyFunc:     deleteChildCAFunc,
		QueryParams:   &resources.QueryParameters{},
		ExtraOpts:     nil,
	})
	if err != nil {
		lFunc.Errorf("could not select child CAs for deletion: %s", err)
		return err
	}

	return nil
}

// revokeChildCAs revokes all child CAs issued by the given CA
func (svc *CAServiceBackend) revokeChildCAs(ctx context.Context, ca *models.CACertificate, lFunc *logrus.Entry) error {

	revokeChildCAFunc := func(childCA models.CACertificate) {
		lFunc.Infof("Revoking child CA %s (%s) issued by CA %s", childCA.ID, childCA.Certificate.Subject.CommonName, ca.ID)
		_, err := svc.service.UpdateCAStatus(ctx, services.UpdateCAStatusInput{
			CAID:             childCA.ID,
			Status:           models.StatusRevoked,
			RevocationReason: ocsp.CessationOfOperation,
		})
		if err != nil {
			lFunc.Errorf("could not revoke child CA %s issued by CA %s: %s", childCA.ID, childCA.Certificate.IssuerCAMetadata.ID, err)
		}
	}

	_, err := svc.caStorage.SelectByParentCA(ctx, ca.ID, storage.StorageListRequest[models.CACertificate]{
		ExhaustiveRun: true,
		ApplyFunc:     revokeChildCAFunc,
		QueryParams:   &resources.QueryParameters{},
		ExtraOpts:     nil,
	})
	if err != nil {
		lFunc.Errorf("could not select child CAs for revocation: %s", err)
		return err
	}

	return nil
}

// deleteCertificatesIssuedByCA deletes all certificates issued by the given CA
func (svc *CAServiceBackend) deleteCertificatesIssuedByCA(ctx context.Context, ca *models.CACertificate, lFunc *logrus.Entry) error {

	ctr := 0
	deleteCertFunc := func(c models.Certificate) {
		lFunc.Infof("Deleting certificate %d - %s", ctr, c.SerialNumber)
		ctr++
		err := svc.service.DeleteCertificate(ctx, services.DeleteCertificateInput{
			SerialNumber: c.SerialNumber,
		})
		if err != nil {
			lFunc.Errorf("could not delete certificate %s issued by CA %s: %s", c.SerialNumber, c.IssuerCAMetadata.ID, err)
		}
	}

	_, err := svc.certStorage.SelectByCA(ctx, ca.ID, storage.StorageListRequest[models.Certificate]{
		ExhaustiveRun: true,
		ApplyFunc:     deleteCertFunc,
		QueryParams:   &resources.QueryParameters{},
		ExtraOpts:     map[string]interface{}{},
	})

	return err
}

// revokeCertificatesIssuedByCA revokes all certificates issued by the given CA
func (svc *CAServiceBackend) revokeCertificatesIssuedByCA(ctx context.Context, ca *models.CACertificate, lFunc *logrus.Entry) error {

	ctr := 0
	revokeCertFunc := func(c models.Certificate) {
		lFunc.Infof("Revoking certificate %d - %s", ctr, c.SerialNumber)
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

	_, err := svc.certStorage.SelectByCA(ctx, ca.ID, storage.StorageListRequest[models.Certificate]{
		ExhaustiveRun: true,
		ApplyFunc:     revokeCertFunc,
		QueryParams:   &resources.QueryParameters{},
		ExtraOpts:     map[string]interface{}{},
	})
	if err != nil {
		lFunc.Errorf("could not revoke certificate %s issued by CA %s", ca.Certificate.SerialNumber, ca.Certificate.IssuerCAMetadata.ID)
	}

	return err
}

// handleCascadeOperations handles the cascade deletion or revocation of child CAs and certificates
func (svc *CAServiceBackend) handleCascadeOperations(ctx context.Context, ca *models.CACertificate, cascadeDelete bool, lFunc *logrus.Entry) error {
	if cascadeDelete {
		// Check if cascade delete is allowed by configuration
		if !svc.allowCascadeDelete {
			lFunc.Errorf("cascade delete operation requested but not allowed by configuration for CA %s", ca.ID)
			return errs.ErrCascadeDeleteNotAllowed
		}

		lFunc.Debugf("cascade delete is enabled and allowed, proceeding with child CA and certificate deletion")

		// Delete child CAs recursively
		if err := svc.deleteChildCAs(ctx, ca, lFunc); err != nil {
			return err
		}

		// Delete all certificates issued by the CA
		return svc.deleteCertificatesIssuedByCA(ctx, ca, lFunc)
	}

	lFunc.Debugf("cascade delete is disabled, proceeding with child CA and certificate revocation")

	// Revoke child CAs issued by the CA
	if err := svc.revokeChildCAs(ctx, ca, lFunc); err != nil {
		return err
	}

	// Revoke all certificates issued by the CA
	return svc.revokeCertificatesIssuedByCA(ctx, ca, lFunc)
}

// deleteCAPrivateKey deletes the private key associated with a CA from its crypto engine
func (svc *CAServiceBackend) deleteCAPrivateKey(ctx context.Context, ca *models.CACertificate, lFunc *logrus.Entry) {
	if ca.Certificate.EngineID == "" {
		lFunc.Debugf("no engine ID specified for CA %s, skipping private key deletion", ca.ID)
		return
	}

	caCert := (*x509.Certificate)(ca.Certificate.Certificate)
	keyID, err := helpers.GetSubjectKeyID(lFunc, caCert)
	if err != nil {
		lFunc.Warnf("could not compute key ID for CA %s: %s", ca.ID, err)
		return
	}

	err = svc.kmsService.DeleteKeyByID(ctx, services.GetKeyInput{
		Identifier: keyID,
	})
	if err != nil {
		lFunc.Warnf("could not delete private key for CA %s from crypto engine %s: %s", ca.ID, ca.Certificate.EngineID, err)
	} else {
		lFunc.Debugf("successfully deleted private key for CA %s from crypto engine %s", ca.ID, ca.Certificate.EngineID)
	}
}

// Returned Error Codes:
//   - ErrCANotFound
//     The specified CA can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
//   - ErrCAStatus
//     Cannot delete a CA that is not expired or revoked.
//   - ErrCascadeDeleteNotAllowed
//     Cascade delete not allowed by configuration.
func (svc *CAServiceBackend) DeleteCA(ctx context.Context, input services.DeleteCAInput) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("DeleteCA struct validation error: %s", err)
		return errs.ErrValidateBadRequest
	}

	ca, err := svc.getCACertificateIfExists(ctx, input.CAID)
	if err != nil {
		return err
	}

	if err := svc.caValidatorCADeletionEligibility(ca, lFunc); err != nil {
		return err
	}

	if err := svc.handleCascadeOperations(ctx, ca, input.CascadeDelete, lFunc); err != nil {
		return err
	}

	// Delete the CA
	err = svc.caStorage.Delete(ctx, input.CAID)
	if err != nil {
		lFunc.Errorf("something went wrong while deleting the CA %s %s", input.CAID, err)
		return err
	}

	// Finally, delete the private key from the crypto engine
	svc.deleteCAPrivateKey(ctx, ca, lFunc)

	return nil
}

func (svc *CAServiceBackend) SignCertificate(ctx context.Context, input services.SignCertificateInput) (*models.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("SignCertificateInput struct validation error: %s", err)
		return nil, errs.ErrCANotFound
	}

	ca, err := svc.getCACertificateIfExists(ctx, input.CAID)
	if err != nil {
		return nil, err
	}

	if ca.Certificate.Status != models.StatusActive {
		lFunc.Errorf("%s CA is not active", ca.ID)
		return nil, errs.ErrCAStatus
	}

	engine := x509engines.NewX509Engine(lFunc, svc.vaServerDomains, svc.kmsService)

	caCert := (*x509.Certificate)(ca.Certificate.Certificate)
	csr := (*x509.CertificateRequest)(input.CertRequest)

	caCertSigner := NewCertificateSigner(ctx, &ca.Certificate, svc.kmsService)

	// Give preference to the embedded IssuanceProfile if it's present
	profile, err := svc.getCaIssuanceProfile(ctx, input.IssuanceProfile, input.IssuanceProfileID, ca.ProfileID)

	lFunc.Debugf("sign certificate request with %s CA", input.CAID)
	x509Cert, err := engine.SignCertificateRequest(ctx, csr, caCert, caCertSigner, *profile)
	if err != nil {
		lFunc.Errorf("could not sign certificate request with %s CA", caCert.Subject.CommonName)
		return nil, err
	}

	ski, err := helpers.GetSubjectKeyID(lFunc, x509Cert)
	if err != nil {
		lFunc.Errorf("could not get Subject Key Identifier for certificate: %s: %s", x509Cert.Subject.CommonName, err)
		return nil, err
	}

	aki, err := helpers.GetSubjectKeyID(lFunc, caCert)
	if err != nil {
		lFunc.Errorf("could not get Authority Key Identifier for CA: %s: %s", caCert.Subject.CommonName, err)
		return nil, err
	}

	cert := models.Certificate{
		VersionSchema: "1.0",
		Metadata:      map[string]interface{}{},
		Type:          models.CertificateTypeImportedWithoutKey,
		Certificate:   (*models.X509Certificate)(x509Cert),
		IssuerCAMetadata: models.IssuerCAMetadata{
			SN: helpers.SerialNumberToHexString(caCert.SerialNumber),
			ID: ca.ID,
		},
		Status:              models.StatusActive,
		KeyMetadata:         helpers.KeyStrengthMetadataFromCertificate(x509Cert),
		Subject:             chelpers.PkixNameToSubject(x509Cert.Subject),
		Issuer:              chelpers.PkixNameToSubject(x509Cert.Issuer),
		SerialNumber:        helpers.SerialNumberToHexString(x509Cert.SerialNumber),
		ValidFrom:           x509Cert.NotBefore,
		ValidTo:             x509Cert.NotAfter,
		RevocationTimestamp: time.Time{},
		IsCA:                x509Cert.IsCA,
		SubjectKeyID:        ski,
		AuthorityKeyID:      aki,
		EngineID:            "",
	}

	// CAs get inserted into the CA storage engine by the CreateCA method. Don't insert them here.
	if !x509Cert.IsCA {
		lFunc.Debugf("insert Certificate %s in storage engine", cert.SerialNumber)
		return svc.certStorage.Insert(ctx, &cert)
	}

	return &cert, nil
}

func (svc *CAServiceBackend) SignChameleonCertificate(ctx context.Context, input services.SignChameleonCertificateInput) (*models.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("SignCertificateInput struct validation error: %s", err)
		return nil, errs.ErrCANotFound
	}

	ca, err := svc.getCACertificateIfExists(ctx, input.CAID)
	if err != nil {
		return nil, err
	}

	if ca.Certificate.Status != models.StatusActive {
		lFunc.Errorf("%s CA is not active", ca.ID)
		return nil, errs.ErrCAStatus
	}

	engine := x509engines.NewX509Engine(lFunc, svc.vaServerDomains, svc.kmsService)

	baseCaCert := (*x509.Certificate)(ca.Certificate.Certificate)
	baseCsr := (*x509.CertificateRequest)(input.BaseCertRequest)

	deltaCaCert, err := x509.ReconstructDeltaCertificate(baseCaCert)
	if err != nil {
		return nil, err
	}
		
	// Update the Subject Key ID of the delta certificate using the saved metadata, so as to 
	// ensure that signing ocurs with the correct key
	// TODO: check if it makes sense to extract this to a function.
	rawDeltaCaSkid, err := hex.DecodeString(ca.Metadata["lamassu.io/certificate/chameleon"].(map[string]any)["delta"].(map[string]any)["akid"].(string))
	if err != nil {
		return nil, err
	}
	deltaCaCert.SubjectKeyId = rawDeltaCaSkid

	deltaCsr := (*x509.CertificateRequest)(input.DeltaCertRequest)

	baseCaCertSigner := NewCertificateSigner(ctx, &ca.Certificate, svc.kmsService)
	deltaCaCertSigner := NewCertificateSigner(ctx, &models.Certificate{
		Certificate: (*models.X509Certificate)(deltaCaCert),
	}, svc.kmsService)

	// Give preference to the embedded IssuanceProfile if it's present
	profile, err := svc.getCaIssuanceProfile(ctx, &input.IssuanceProfile, input.IssuanceProfileID, ca.ProfileID)
	if err != nil {
		return nil, err
	}

	lFunc.Debugf("sign certificate request with %s CA", input.CAID)
	x509Cert, err := engine.SignChameleonCertificateRequest(ctx, deltaCsr, baseCsr, baseCaCert, deltaCaCertSigner, baseCaCertSigner, *profile)
	if err != nil {
		lFunc.Errorf("could not sign certificate request with %s CA", baseCaCert.Subject.CommonName)
		return nil, err
	}

	ski, err := helpers.GetSubjectKeyID(lFunc, x509Cert)
	if err != nil {
		lFunc.Errorf("could not get Subject Key Identifier for certificate: %s: %s", x509Cert.Subject.CommonName, err)
		return nil, err
	}

	aki, err := helpers.GetSubjectKeyID(lFunc, baseCaCert)
	if err != nil {
		lFunc.Errorf("could not get Authority Key Identifier for CA: %s: %s", baseCaCert.Subject.CommonName, err)
		return nil, err
	}

	cert := models.Certificate{
		VersionSchema: "1.0",
		Metadata:      map[string]interface{}{},
		Certificate:   (*models.X509Certificate)(x509Cert),
		IssuerCAMetadata: models.IssuerCAMetadata{
			SN: helpers.SerialNumberToHexString(baseCaCert.SerialNumber),
			ID: ca.ID,
		},
		Status:              models.StatusActive,
		KeyMetadata:         helpers.KeyStrengthMetadataFromCertificate(x509Cert),
		Subject:             chelpers.PkixNameToSubject(x509Cert.Subject),
		Issuer:              chelpers.PkixNameToSubject(x509Cert.Issuer),
		SerialNumber:        helpers.SerialNumberToHexString(x509Cert.SerialNumber),
		ValidFrom:           x509Cert.NotBefore,
		ValidTo:             x509Cert.NotAfter,
		RevocationTimestamp: time.Time{},
		IsCA:                x509Cert.IsCA,
		SubjectKeyID:        ski,
		AuthorityKeyID:      aki,
		EngineID:            "",
	}

	// CAs get inserted into the CA storage engine by the CreateCA method. Don't insert them here.
	if !x509Cert.IsCA {
		lFunc.Debugf("insert Certificate %s in storage engine", cert.SerialNumber)
		return svc.certStorage.Insert(ctx, &cert)
	}

	return &cert, nil
}

func (svc *CAServiceBackend) getCaIssuanceProfile(ctx context.Context, inputProfile *models.IssuanceProfile, inputProfileID string, caProfileID string) (*models.IssuanceProfile, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	var profile *models.IssuanceProfile
	var err error
	
	if inputProfile != nil {
		profile = inputProfile
	} else if inputProfileID != "" {
		profile, err = svc.service.GetIssuanceProfileByID(ctx, services.GetIssuanceProfileByIDInput{
			ProfileID: inputProfileID,
		})
		if err != nil {
			lFunc.Errorf("could not get issuance profile %s: %s", inputProfileID, err)
			return nil, err
		}
	} else {
		// Use the CA default profile
		profile, err = svc.service.GetIssuanceProfileByID(ctx, services.GetIssuanceProfileByIDInput{
			ProfileID: caProfileID,
		})
		if err != nil {
			lFunc.Errorf("could not get default ca issuance profile %s: %s", caProfileID, err)
			return nil, err
		}
	}

	return profile, nil
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
	status := models.StatusActive
	if input.Certificate.NotAfter.Before(time.Now()) {
		status = models.StatusExpired
	}

	skid, err := helpers.GetSubjectKeyID(lFunc, x509Cert)
	if err != nil {
		lFunc.Errorf("could not get Subject Key Identifier for certificate: %s: %s", x509Cert.Subject.CommonName, err)
		return nil, err
	}

	newCert := models.Certificate{
		VersionSchema:       "unknown",
		Metadata:            input.Metadata,
		Type:                models.CertificateTypeImportedWithoutKey,
		Certificate:         (*models.X509Certificate)(input.Certificate),
		Status:              status,
		KeyMetadata:         helpers.KeyStrengthMetadataFromCertificate(x509Cert),
		Subject:             chelpers.PkixNameToSubject(input.Certificate.Subject),
		SerialNumber:        helpers.SerialNumberToHexString(input.Certificate.SerialNumber),
		ValidFrom:           input.Certificate.NotBefore,
		ValidTo:             input.Certificate.NotAfter,
		RevocationTimestamp: time.Time{},
		IsCA:                x509Cert.IsCA,
		SubjectKeyID:        skid,
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
		newCert.AuthorityKeyID = parentCA.Certificate.SubjectKeyID
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

	err := caValidator.Struct(input)
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

	certSigner := NewCertificateSigner(ctx, &ca.Certificate, svc.kmsService)

	lFunc.Debugf("sign signature with %s Certificate", ca.Certificate.SerialNumber)

	var opts crypto.SignerOpts
	hash := crypto.SHA256

	algo := strings.ToUpper(input.SigningAlgorithm)
	switch {
	case strings.Contains(algo, "SHA_256"):
		hash = crypto.SHA256
	case strings.Contains(algo, "SHA_384"):
		hash = crypto.SHA384
	case strings.Contains(algo, "SHA_512"):
		hash = crypto.SHA512
	}

	if input.MessageType == models.Raw {
		hashFunc := hash.New()
		_, err = hashFunc.Write(input.Message)
		if err != nil {
			return nil, err
		}
		hashed := hashFunc.Sum(nil)

		input.Message = hashed
	}

	if strings.HasPrefix(input.SigningAlgorithm, "RSASSA_PSS") {
		opts = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hash,
		}
	} else {
		opts = hash
	}

	signature, err := certSigner.Sign(rand.Reader, input.Message, opts)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (svc *CAServiceBackend) SignatureVerify(ctx context.Context, input services.SignatureVerifyInput) (bool, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := caValidator.Struct(input)
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

	res, err := svc.kmsService.VerifySignature(ctx, services.VerifySignInput{
		Identifier:  ca.Certificate.SubjectKeyID,
		Algorithm:   input.SigningAlgorithm,
		Message:     input.Message,
		Signature:   input.Signature,
		MessageType: input.MessageType,
	})
	if err != nil {
		lFunc.Errorf("could not verify signature with CA %s: %s", ca.Certificate.SerialNumber, err)
		return false, err
	}

	return res.Valid, nil
}

// Returned Error Codes:
//   - ErrCertificateNotFound
//     The specified Certificate can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
func (svc *CAServiceBackend) GetCertificateBySerialNumber(ctx context.Context, input services.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := caValidator.Struct(input)
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

	err := caValidator.Struct(input)
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

	err := caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateCertificateStatus struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if certificate '%s' exists", input.SerialNumber)
	cert, err := svc.service.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: input.SerialNumber,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while checking if certificate '%s' exists in storage engine: %s", input.SerialNumber, err)
		return nil, err
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

	err := caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateCertificateMetadataInput struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if certificate '%s' exists", input.SerialNumber)
	cert, err := svc.service.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: input.SerialNumber,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while checking if certificate '%s' exists in storage engine: %s", input.SerialNumber, err)
		return nil, err
	}

	updatedMetadata, err := chelpers.ApplyPatches[map[string]any](cert.Metadata, input.Patches)
	if err != nil {
		lFunc.Errorf("failed to apply patches to metadata for Certificate '%s': %v", input.SerialNumber, err)
		return nil, err
	}

	cert.Metadata = *updatedMetadata

	lFunc.Debugf("updating %s certificate metadata", input.SerialNumber)
	return svc.certStorage.Update(ctx, cert)
}

// Returned Error Codes:
//   - ErrCertificateNotFound
//     The specified Certificate can not be found in the Database
//   - ErrValidateBadRequest
//     The required variables of the data structure are not valid.
//   - ErrCertificateIssuerCAExists
//     Cannot delete certificate because the issuer CA still exists in the system.
func (svc *CAServiceBackend) DeleteCertificate(ctx context.Context, input services.DeleteCertificateInput) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := caValidator.Struct(input)
	if err != nil {
		lFunc.Errorf("DeleteCertificateInput struct validation error: %s", err)
		return errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if certificate '%s' exists", input.SerialNumber)
	cert, err := svc.service.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: input.SerialNumber,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while checking if certificate '%s' exists in storage engine: %s", input.SerialNumber, err)
		return err
	}

	// Check if the issuer CA still exists in the system
	lFunc.Debugf("checking if issuer CA '%s' still exists for certificate '%s'", cert.IssuerCAMetadata.ID, input.SerialNumber)
	_, err = svc.getCACertificateIfExists(ctx, cert.IssuerCAMetadata.ID)
	if err == nil {
		// Issuer CA exists, reject deletion
		lFunc.Errorf("cannot delete certificate %s: issuer CA %s still exists in the system", input.SerialNumber, cert.IssuerCAMetadata.ID)
		return errs.ErrCertificateIssuerCAExists
	} else if err != errs.ErrCANotFound {
		// Some other error occurred while checking CA existence
		lFunc.Errorf("error while checking if issuer CA '%s' exists: %s", cert.IssuerCAMetadata.ID, err)
		return err
	}

	// Issuer CA does not exist, proceed with deletion
	lFunc.Debugf("issuer CA '%s' not found, proceeding with certificate deletion", cert.IssuerCAMetadata.ID)
	lFunc.Debugf("deleting certificate %s from storage engine", input.SerialNumber)
	err = svc.certStorage.Delete(ctx, input.SerialNumber)
	if err != nil {
		lFunc.Errorf("something went wrong while deleting certificate '%s' from storage engine: %s", input.SerialNumber, err)
		return err
	}

	return nil
}

func createCAValidation(sl validator.StructLevel) {
	ca := sl.Current().Interface().(services.CreateCAInput)
	if !helpers.ValidateValidity(ca.CAExpiration) {
		// lFunc.Errorf("CA Expiration time ref is incompatible with the selected variable")
		sl.ReportError(ca.CAExpiration, "CAExpiration", "CAExpiration", "InvalidCAExpiration", "")
	}
}

func (svc *CAServiceBackend) GetIssuanceProfiles(ctx context.Context, input services.GetIssuanceProfilesInput) (string, error) {
	return svc.issuanceProfilesStorage.SelectAll(ctx, storage.StorageListRequest[models.IssuanceProfile]{
		ExhaustiveRun: input.ExhaustiveRun,
		ApplyFunc:     input.ApplyFunc,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     map[string]interface{}{},
	})
}

func (svc *CAServiceBackend) GetIssuanceProfileByID(ctx context.Context, input services.GetIssuanceProfileByIDInput) (*models.IssuanceProfile, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	exists, profile, err := svc.issuanceProfilesStorage.SelectByID(ctx, input.ProfileID)
	if err != nil {
		return nil, err
	}

	if !exists {
		lFunc.Errorf("issuance profile '%s' does not exist", input.ProfileID)
		return nil, errs.ErrIssuanceProfileNotFound
	}

	return profile, nil
}

func (svc *CAServiceBackend) CreateIssuanceProfile(ctx context.Context, input services.CreateIssuanceProfileInput) (*models.IssuanceProfile, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)
	id := uuid.NewString()
	input.Profile.ID = id
	lFunc.Infof("creating issuance profile '%s' with ID '%s'", input.Profile.Name, id)

	if input.Profile.ExtendedKeyUsages == nil {
		input.Profile.ExtendedKeyUsages = []models.X509ExtKeyUsage{}
	}

	p, err := svc.issuanceProfilesStorage.Insert(ctx, &input.Profile)
	if err != nil {
		lFunc.Errorf("could not create issuance profile '%s': %s", input.Profile.Name, err)
		return nil, err
	}

	lFunc.Infof("issuance profile '%s' with ID '%s' created successfully", input.Profile.Name, id)
	return p, nil
}

func (svc *CAServiceBackend) UpdateIssuanceProfile(ctx context.Context, input services.UpdateIssuanceProfileInput) (*models.IssuanceProfile, error) {
	return svc.issuanceProfilesStorage.Update(ctx, &input.Profile)
}

func (svc *CAServiceBackend) DeleteIssuanceProfile(ctx context.Context, input services.DeleteIssuanceProfileInput) error {
	return svc.issuanceProfilesStorage.Delete(ctx, input.ProfileID)
}
