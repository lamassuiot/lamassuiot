package services

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/engines/crypto/software"
	"github.com/sirupsen/logrus"
	"gocloud.dev/blob"
	"gocloud.dev/gcerrors"

	"github.com/lamassuiot/lamassuiot/v4/sdk"
	"go.opentelemetry.io/otel"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

var crlValidate *validator.Validate

type CRLServiceBackend struct {
	caSDK      services.CAService
	kmsService services.KMSService
	logger     *logrus.Entry
	vaRepo     storage.CRLSettingsRepo
	service    services.CRLService
	bucket     *blob.Bucket
	vaDomains  []string
}

type CRLServiceBuilder struct {
	VARepo    storage.CRLSettingsRepo
	Logger    *logrus.Entry
	CAClient  services.CAService
	KMSClient services.KMSService
	Bucket    *blob.Bucket
	VADomains []string
}

type CRLMiddleware func(services.CRLService) services.CRLService

func NewCRLService(builder CRLServiceBuilder) (services.CRLService, error) {
	crlValidate = validator.New()

	svc := &CRLServiceBackend{
		caSDK:      builder.CAClient,
		kmsService: builder.KMSClient,
		logger:     builder.Logger,
		vaRepo:     builder.VARepo,
		bucket:     builder.Bucket,
		vaDomains:  builder.VADomains,
	}

	svc.service = svc

	return svc, nil
}

func (svc *CRLServiceBackend) SetService(service services.CRLService) {
	svc.service = service
}

func crlObjectKey(id, version string) string {
	return fmt.Sprintf("pki/va/crl/%s/%s.crl", id, version)
}

// resolveCRLSettings finds the settings an URL segment refers to: the ID of a CA or, for the CDP of the certificates
// issued before the settings moved to the CA ID, the SKI of its key. The old form is only looked up among the SKIs the
// migration recorded: it is never resolved by searching "the CA with this SKI", so a CA created later on the same key
// cannot take over an existing URL.
func (svc CRLServiceBackend) resolveCRLSettings(ctx context.Context, id string) (*models.CRLSettings, error) {
	exists, settings, err := svc.vaRepo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if exists {
		return settings, nil
	}

	exists, settings, err = svc.vaRepo.GetByLegacySKI(ctx, id)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errs.ErrCRLSettingsNotFound
	}
	return settings, nil
}

func (svc CRLServiceBackend) GetCRL(ctx context.Context, input services.GetCRLInput) (*x509.RevocationList, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := crlValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	settings, err := svc.resolveCRLSettings(ctx, input.ID)
	if err != nil {
		lFunc.Errorf("could not resolve CRL settings %s: %s", input.ID, err)
		return nil, err
	}

	versionStr := input.CRLVersion.String()
	if input.CRLVersion.Cmp(big.NewInt(0)) == 0 {
		versionStr = settings.LatestCRL.Version.String()
	}

	crlPem, err := svc.bucket.ReadAll(ctx, crlObjectKey(settings.CAID, versionStr))
	if gcerrors.Code(err) == gcerrors.NotFound && settings.LegacySKI != nil {
		// CRLs published before the settings moved to the CA ID stay where they were written.
		crlPem, err = svc.bucket.ReadAll(ctx, crlObjectKey(*settings.LegacySKI, versionStr))
	}

	// If the requested version is 0 (latest) and it is not found, try the previous version.
	// This can happen if a CRL was generated but not published yet, and the request is made before
	// the publish operation completes. This is a temporary workaround until the CRL generation and
	// publishing process is improved.
	if gcerrors.Code(err) == gcerrors.NotFound && input.CRLVersion.Sign() == 0 && settings.LatestCRL.Version.Int != nil && settings.LatestCRL.Version.Cmp(big.NewInt(1)) > 0 {
		versionStr = new(big.Int).Sub(settings.LatestCRL.Version.Int, big.NewInt(1)).String()
		crlPem, err = svc.bucket.ReadAll(ctx, crlObjectKey(settings.CAID, versionStr))
		if gcerrors.Code(err) == gcerrors.NotFound && settings.LegacySKI != nil {
			crlPem, err = svc.bucket.ReadAll(ctx, crlObjectKey(*settings.LegacySKI, versionStr))
		}
	}

	if gcerrors.Code(err) == gcerrors.NotFound {
		lFunc.Errorf("CRL %s of CA %s is not published", versionStr, settings.CAID)
		return nil, errs.ErrCRLNotFound
	}

	if err != nil {
		lFunc.Errorf("something went wrong while reading CRL: %s", err)
		return nil, err
	}

	crlDer, _ := pem.Decode(crlPem)
	if crlDer == nil {
		return nil, fmt.Errorf("CRL %s of CA %s is not PEM encoded", versionStr, settings.CAID)
	}

	crl, err := x509.ParseRevocationList(crlDer.Bytes)
	if err != nil {
		lFunc.Errorf("something went wrong while parsing CRL: %s", err)
		return nil, err
	}

	return crl, nil
}

func (svc CRLServiceBackend) InitCRLSettings(ctx context.Context, caID string) (*models.CRLSettings, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	ca, err := svc.caSDK.GetCAByID(ctx, services.GetCAByIDInput{CAID: caID})
	if err != nil {
		lFunc.Errorf("could not get CA %s: %s", caID, err)
		return nil, err
	}

	// One settings per CA, even for CAs sharing a key. An existing one means the event is being retried.
	exists, existing, err := svc.vaRepo.Get(ctx, caID)
	if err != nil {
		return nil, err
	}
	if exists {
		lFunc.Infof("CRL settings for CA %s already exist, keeping them", caID)
		return existing, nil
	}

	settings, err := svc.vaRepo.Insert(ctx, &models.CRLSettings{
		CAID:   caID,
		Status: models.CRLSettingsActive,
		Options: models.CRLSettingsOptions{
			Validity:           models.TimeDuration(24 * time.Hour * 7),            // 1 week
			RefreshInterval:    models.TimeDuration(24*time.Hour*6 + 23*time.Hour), // 6 days, 23 hours
			RegenerateOnRevoke: true,
			SignerSerialNumber: ca.Certificate.SerialNumber,
		},
		LatestCRL: models.LatestCRLMeta{
			Version:   models.BigInt{Int: big.NewInt(0)},
			ValidFrom: time.Now(),
		},
	})
	if err != nil {
		return nil, err
	}

	_, err = svc.service.CalculateCRL(ctx, services.CalculateCRLInput{
		CAID: caID,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while calculating first CRL: %s", err)
		return nil, err
	}

	return settings, nil
}

func (svc CRLServiceBackend) CalculateCRL(ctx context.Context, input services.CalculateCRLInput) (*x509.RevocationList, error) {
	ctx, span := otel.GetTracerProvider().Tracer("VA Service").Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName("Lamassu-Monolithic")))
	defer span.End()

	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := crlValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	exists, settings, err := svc.vaRepo.Get(ctx, input.CAID)
	if err != nil {
		lFunc.Errorf("something went wrong while reading CRL settings: %s", err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("CRL settings for CA %s do not exist", input.CAID)
		return nil, errs.ErrCRLSettingsNotFound
	}

	if settings.Status != models.CRLSettingsActive {
		lFunc.Warnf("CRL settings for CA %s are %s: not generating a CRL", input.CAID, settings.Status)
		return nil, errs.ErrCRLSettingsNotActive
	}

	crlCA, signerCert, err := svc.crlIssuer(ctx, input.CAID, settings.Options.SignerSerialNumber)
	if err != nil {
		return nil, err
	}

	certList := []x509.RevocationListEntry{}
	lFunc.Debugf("reading CA %s certificates", crlCA.ID)
	_, err = svc.caSDK.GetCertificatesByCaAndStatus(ctx, services.GetCertificatesByCaAndStatusInput{
		CAID:   crlCA.ID,
		Status: models.StatusRevoked,
		ListInput: resources.ListInput[models.Certificate]{
			ExhaustiveRun: true,
			QueryParameters: &resources.QueryParameters{
				PageSize: 15,
			},
			ApplyFunc: func(cert models.Certificate) {
				certList = append(certList, x509.RevocationListEntry{
					SerialNumber:   cert.Certificate.SerialNumber,
					RevocationTime: cert.RevocationTimestamp,
					Extensions:     []pkix.Extension{},
					ReasonCode:     int(cert.RevocationReason),
				})
			},
		},
	})
	if err != nil {
		lFunc.Errorf("something went wrong while reading CA %s certificates: %s", crlCA.ID, err)
		return nil, err
	}

	crlSigner := NewCertificateSigner(ctx, signerCert, svc.kmsService)
	caCert := (*x509.Certificate)(signerCert.Certificate)

	extensions := []pkix.Extension{}

	idp, err := svc.getDistributionPointExtension(crlCA.ID, settings.LegacySKI)
	if err != nil {
		lFunc.Errorf("something went wrong while creating Issuing Distribution Point extension: %s", err)
		return nil, err
	}

	extensions = append(extensions, *idp)

	lFunc.Debugf("creating revocation list. CA %s", crlCA.ID)
	now := time.Now()

	previousVersion := big.NewInt(0)
	if settings.LatestCRL.Version.Int != nil {
		previousVersion.Set(settings.LatestCRL.Version.Int)
	}
	crlVersion := new(big.Int).Add(previousVersion, big.NewInt(1))

	entropy := software.NewLamassuEntropy(ctx)

	crlDer, err := x509.CreateRevocationList(entropy, &x509.RevocationList{
		RevokedCertificateEntries: certList,
		Number:                    crlVersion,
		ThisUpdate:                now,
		NextUpdate:                now.Add(time.Duration(settings.Options.Validity)),
		ExtraExtensions:           extensions,
	}, caCert, crlSigner)
	if err != nil {
		lFunc.Errorf("something went wrong while creating revocation list: %s", err)
		return nil, err
	}

	crl, err := x509.ParseRevocationList(crlDer)
	if err != nil {
		lFunc.Errorf("something went wrong while parsing revocation list: %s", err)
		return nil, err
	}

	// Another writer may have generated this version meanwhile, from a different list of revocations. The version is
	// claimed first, so the file at its final path is only ever written by the generation that won it: the CRL is
	// staged in a private file, and moved to its path once the claim succeeds.
	crlPem := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDer})
	finalKey := crlObjectKey(crlCA.ID, crl.Number.String())
	nonce := make([]byte, 8)
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	stagedKey := finalKey + "." + hex.EncodeToString(nonce) + ".tmp"
	err = svc.bucket.WriteAll(ctx, stagedKey, crlPem, nil)
	if err != nil {
		lFunc.Errorf("something went wrong while saving CRL: %s", err)
		return nil, err
	}
	defer func() { _ = svc.bucket.Delete(context.WithoutCancel(ctx), stagedKey) }()

	err = svc.vaRepo.UpdateLatestCRL(ctx, crlCA.ID, previousVersion, models.LatestCRLMeta{
		Version:    models.BigInt{Int: crl.Number},
		ValidFrom:  crl.ThisUpdate,
		ValidUntil: crl.NextUpdate,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while updating CRL settings: %s", err)
		return nil, err
	}

	err = svc.bucket.Copy(ctx, finalKey, stagedKey, nil)
	if err != nil {
		lFunc.Errorf("something went wrong while publishing CRL: %s", err)
		if rollbackErr := svc.vaRepo.UpdateLatestCRL(context.WithoutCancel(ctx), crlCA.ID, crl.Number, settings.LatestCRL); rollbackErr != nil {
			lFunc.Errorf("could not restore previous CRL settings: %s", rollbackErr)
		}
		return nil, err
	}

	return crl, nil
}

func (svc CRLServiceBackend) GetCRLSettings(ctx context.Context, input services.GetCRLSettingsInput) (*models.CRLSettings, error) {
	exists, settings, err := svc.vaRepo.Get(ctx, input.CAID)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, errs.ErrCRLSettingsNotFound
	}

	return settings, nil
}

func (svc CRLServiceBackend) GetCRLSettingsList(ctx context.Context, input services.GetCRLSettingsListInput) (string, error) {
	return svc.vaRepo.GetAll(ctx, storage.StorageListRequest[models.CRLSettings]{
		ExhaustiveRun: input.ExhaustiveRun,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     map[string]any{},
		ApplyFunc: func(settings models.CRLSettings) {
			input.ApplyFunc(settings)
		},
	})
}

func (svc CRLServiceBackend) UpdateCRLSettings(ctx context.Context, input services.UpdateCRLSettingsInput) (*models.CRLSettings, error) {
	if err := crlValidate.Struct(input); err != nil {
		return nil, errs.ErrValidateBadRequest
	}

	exists, settings, err := svc.vaRepo.Get(ctx, input.CAID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errs.ErrCRLSettingsNotFound
	}

	if settings.Status != models.CRLSettingsActive {
		return nil, errs.ErrCRLSettingsNotActive
	}

	// A signer that is kept is not checked again: an unrelated edit must not fail because of it (#841).
	if input.Options.SignerSerialNumber != settings.Options.SignerSerialNumber {
		if _, _, err := svc.crlIssuer(ctx, input.CAID, input.Options.SignerSerialNumber); err != nil {
			return nil, err
		}
	}

	return svc.vaRepo.UpdateOptions(ctx, input.CAID, input.Options)
}

// getDistributionPointExtension builds the IDP of the CRL of a CA: the URLs of every certificate it covers. For
// migrated settings those are the new one and the old one (/crl/<ski>) of each VA domain, since RFC 5280 6.3.3 requires
// the IDP to match the CDP of the certificate.
func (svc CRLServiceBackend) getDistributionPointExtension(caID string, legacySKI *string) (*pkix.Extension, error) {
	type DistributionPointName struct { // CHOICE
		FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
		RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
	}

	// RFC 5280. Section 5.2.5,
	type IssuingDistributionPoint struct {
		DistributionPoint          DistributionPointName `asn1:"tag:0,optional"`
		OnlyContainsUserCerts      bool                  `asn1:"tag:1"`
		OnlyContainsCACerts        bool                  `asn1:"tag:2"`
		OnlySomeReasons            asn1.BitString        `asn1:"tag:3,optional"`
		IndirectCRL                bool                  `asn1:"tag:4"`
		OnlyContainsAttributeCerts bool                  `asn1:"tag:5"`
	}

	idpNames := []asn1.RawValue{}
	for _, name := range svc.vaDomains {
		ids := []string{caID}
		if legacySKI != nil {
			ids = append(ids, *legacySKI)
		}
		for _, id := range ids {
			idpNames = append(idpNames, asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(fmt.Sprintf("http://%s/crl/%s", name, url.PathEscape(id)))})
		}
	}

	// Add Issuing Distribution Point
	idp, err := asn1.Marshal(IssuingDistributionPoint{
		DistributionPoint: DistributionPointName{
			FullName: idpNames,
		},
	})
	if err != nil {
		return nil, err
	}

	return &pkix.Extension{
		Id:       []int{2, 5, 29, 28},
		Critical: true,
		Value:    idp,
	}, nil
}

// crlIssuer resolves the CA that issues the CRL of some CRL settings and checks that the certificate is a valid signer
// for it. These are direct CRLs: the signer has the identity of the issuer (its subject and its key) and the cRLSign key
// usage, since changing the issuer would require indirect-CRL support, not just a different signature. The signer is
// compared with the identity of the CA, not with its current certificate, so any certificate of the CA is valid: its
// reissued ones and, eventually, its cross-signed ones.
func (svc CRLServiceBackend) crlIssuer(ctx context.Context, caID, serial string) (*models.CACertificate, *models.Certificate, error) {
	cert, err := svc.caSDK.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: serial})
	if err != nil {
		return nil, nil, err
	}

	ca, err := svc.caSDK.GetCAByID(ctx, services.GetCAByIDInput{CAID: caID})
	if err != nil {
		return nil, nil, err
	}

	signer := (*x509.Certificate)(cert.Certificate)
	caCert := (*x509.Certificate)(ca.Certificate.Certificate)
	signerKey, err := x509.MarshalPKIXPublicKey(signer.PublicKey)
	if err != nil || signer.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, nil, errs.ErrValidateBadRequest
	}
	caKey, err := x509.MarshalPKIXPublicKey(caCert.PublicKey)
	if err != nil || !bytes.Equal(caCert.RawSubject, signer.RawSubject) || !bytes.Equal(caKey, signerKey) {
		return nil, nil, errs.ErrValidateBadRequest
	}

	return ca, cert, nil
}
