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
	"errors"
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
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/revocation"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/engines/crypto/software"
	"github.com/sirupsen/logrus"
	"gocloud.dev/blob"
	"gocloud.dev/gcerrors"
	"golang.org/x/crypto/ocsp"

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
		if err == nil {
			lFunc.Warnf("serving CRL version %s of CA %s: latest version %s is not published", versionStr, settings.CAID, settings.LatestCRL.Version.String())
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

	// ACTIVE settings retain the key of their signer (crl_settings_signer_key_fk), and a CA without a key in the KMS
	// cannot sign CRLs anyway. It gets no settings, and this is not an error: the event would be redelivered forever.
	if ca.Certificate.EngineID == "" || ca.Certificate.KeyID == "" {
		lFunc.Warnf("CA %s has no key in the KMS: it cannot sign CRLs, so no CRL settings are created", caID)
		return nil, nil
	}

	// The CRL of a CA is signed by the CA itself, so its certificate needs the cRLSign key usage, which crlIssuer
	// checks on every CRL. An imported certificate may not have it: it gets no settings either, rather than ACTIVE
	// ones whose CRL could never be issued. Like the check above, this is not an error.
	caCert := (*x509.Certificate)(ca.Certificate.Certificate)
	if caCert == nil || caCert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		lFunc.Warnf("the certificate of CA %s cannot sign CRLs (it needs the cRLSign key usage), so no CRL settings are created", caID)
		return nil, nil
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
		SignerEngineID: &ca.Certificate.EngineID,
		SignerKeyID:    &ca.Certificate.KeyID,
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

	validity := time.Duration(settings.Options.Validity)
	return svc.calculateCRL(ctx, settings, func(now time.Time) time.Time { return now.Add(validity) })
}

// calculateCRL generates and publishes the next CRL of ACTIVE settings, valid until nextUpdate(now). It does not need
// the CA to exist: the revocations are listed by the CA ID, which outlives the CA.
func (svc CRLServiceBackend) calculateCRL(ctx context.Context, settings *models.CRLSettings, nextUpdate func(now time.Time) time.Time) (*x509.RevocationList, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)
	caID := settings.CAID

	// The signer is checked against the identity of the CA while the CA exists: the database only knows that it is a
	// certificate. Once the CA is gone, the signer validated when it was set is used as it is.
	_, signerCert, err := svc.crlIssuer(ctx, caID, settings.Options.SignerSerialNumber)
	if errors.Is(err, errs.ErrCANotFound) {
		signerCert, err = svc.caSDK.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: settings.Options.SignerSerialNumber})
	}
	if err != nil {
		lFunc.Errorf("could not get a valid CRL signer %s for CA %s: %s", settings.Options.SignerSerialNumber, caID, err)
		return nil, err
	}

	certList := []x509.RevocationListEntry{}
	lFunc.Debugf("reading CA %s certificates", caID)
	_, err = svc.caSDK.GetCertificatesByCaAndStatus(ctx, services.GetCertificatesByCaAndStatusInput{
		CAID:   caID,
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
		lFunc.Errorf("something went wrong while reading CA %s certificates: %s", caID, err)
		return nil, err
	}

	crlSigner := NewCertificateSigner(ctx, signerCert, svc.kmsService)
	caCert := (*x509.Certificate)(signerCert.Certificate)

	extensions := []pkix.Extension{}

	idp, err := svc.getDistributionPointExtension(caID, settings.LegacySKI)
	if err != nil {
		lFunc.Errorf("something went wrong while creating Issuing Distribution Point extension: %s", err)
		return nil, err
	}

	extensions = append(extensions, *idp)

	lFunc.Debugf("creating revocation list. CA %s", caID)
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
		NextUpdate:                nextUpdate(now),
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
	finalKey := crlObjectKey(caID, crl.Number.String())
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

	err = svc.vaRepo.UpdateLatestCRL(ctx, caID, previousVersion, models.LatestCRLMeta{
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
		if rollbackErr := svc.vaRepo.UpdateLatestCRL(context.WithoutCancel(ctx), caID, crl.Number, settings.LatestCRL); rollbackErr != nil {
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
	signerKey := models.CRLSignerKey{EngineID: deref(settings.SignerEngineID), KeyID: deref(settings.SignerKeyID)}
	if input.Options.SignerSerialNumber != settings.Options.SignerSerialNumber {
		_, signer, err := svc.crlIssuer(ctx, input.CAID, input.Options.SignerSerialNumber)
		if err != nil {
			return nil, err
		}
		// ACTIVE settings retain the key of their signer, so a signer has to have one in the KMS.
		if signer.KeyID == "" {
			return nil, errs.ErrValidateBadRequest
		}
		signerKey = models.CRLSignerKey{EngineID: signer.EngineID, KeyID: signer.KeyID}
	}

	return svc.vaRepo.UpdateOptions(ctx, input.CAID, input.Options, signerKey)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// finalCRLAttempts bounds how many times FinalizeCRLSettings issues the final CRL again when another CRL gets
// published between the final CRL and the transition to FINAL.
const finalCRLAttempts = 3

func (svc CRLServiceBackend) FinalizeCRLSettings(ctx context.Context, input services.FinalizeCRLSettingsInput) (*models.CRLSettings, *x509.RevocationList, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)
	if err := crlValidate.Struct(input); err != nil {
		return nil, nil, errs.ErrValidateBadRequest
	}

	for attempt := 1; ; attempt++ {
		settings, err := svc.GetCRLSettings(ctx, services.GetCRLSettingsInput{CAID: input.CAID})
		if err != nil {
			return nil, nil, err
		}
		if settings.Status != models.CRLSettingsActive {
			// Transitions only move forward: a retried event finds them done.
			return settings, nil, nil
		}

		// The final CRL is published while the settings are still ACTIVE, so its key is still retained, and they only
		// move to FINAL while it is still their latest CRL: a regular CRL published meanwhile would otherwise replace it,
		// and expire long before the CA.
		var finalVersion *big.Int
		var finalCRL *x509.RevocationList
		if input.FinalCRL {
			crl, err := svc.calculateCRL(ctx, settings, func(time.Time) time.Time { return input.FinalCRLNextUpdate })
			if err == nil {
				finalVersion = crl.Number
				err = svc.vaRepo.MarkFinal(ctx, input.CAID, finalVersion)
			}
			if errors.Is(err, errs.ErrCRLSettingsConflict) && attempt < finalCRLAttempts {
				lFunc.Warnf("another CRL of CA %s was published along its final CRL: issuing the final CRL again", input.CAID)
				continue
			}
			if errors.Is(err, errs.ErrCRLSettingsNotActive) {
				// Another finalizer got there first: reading them again finds them done.
				lFunc.Infof("CRL settings of CA %s were finalized meanwhile", input.CAID)
				continue
			}
			if err != nil {
				lFunc.Errorf("could not issue the final CRL of CA %s: %s", input.CAID, err)
				return nil, nil, err
			}
			finalCRL = crl
			lFunc.Infof("final CRL %s of CA %s issued, valid until %s", finalVersion, input.CAID, input.FinalCRLNextUpdate)
		} else if err := svc.vaRepo.MarkFinal(ctx, input.CAID, nil); err != nil {
			return nil, nil, err
		}

		finalSettings, err := svc.GetCRLSettings(ctx, services.GetCRLSettingsInput{CAID: input.CAID})
		if err != nil {
			// The final CRL is issued and the settings are FINAL: it is returned so that it is still announced.
			return nil, finalCRL, err
		}
		return finalSettings, finalCRL, nil
	}
}

// ArchiveCRLSettings archives the settings of a deleted CA. Settings still ACTIVE at that point (their signer was not
// one of the certificates the CA released, or an event was lost) still retain the key of their signer, so they first
// get a final CRL, valid until the signer expires: archiving must never leave the last CRL a short-lived one.
func (svc CRLServiceBackend) ArchiveCRLSettings(ctx context.Context, input services.ArchiveCRLSettingsInput) (*models.CRLSettings, error) {
	if err := crlValidate.Struct(input); err != nil {
		return nil, errs.ErrValidateBadRequest
	}

	settings, err := svc.GetCRLSettings(ctx, services.GetCRLSettingsInput{CAID: input.CAID})
	if err != nil {
		return nil, err
	}
	if settings.Status == models.CRLSettingsActive {
		signer, err := svc.caSDK.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: settings.Options.SignerSerialNumber})
		if err != nil {
			return nil, err
		}
		finalize := services.FinalizeCRLSettingsInput{CAID: input.CAID}
		if signer.ValidTo.After(time.Now()) {
			finalize.FinalCRL, finalize.FinalCRLNextUpdate = true, signer.ValidTo
		}
		if _, _, err := svc.service.FinalizeCRLSettings(ctx, finalize); err != nil {
			return nil, err
		}
	}

	if err := svc.vaRepo.MarkArchived(ctx, input.CAID); err != nil {
		return nil, err
	}
	return svc.GetCRLSettings(ctx, services.GetCRLSettingsInput{CAID: input.CAID})
}

func (svc CRLServiceBackend) DeleteCRLSettings(ctx context.Context, input services.DeleteCRLSettingsInput) error {
	if err := crlValidate.Struct(input); err != nil {
		return errs.ErrValidateBadRequest
	}
	return svc.vaRepo.Delete(ctx, input.CAID)
}

// ReconcileCRLSettings brings the settings in line with their CA, reading it again rather than trusting an event that
// may be stale or redelivered: a deleted CA archives them, and an ACTIVE settings of a revoked (not on hold) CA gets its
// final CRL and turns FINAL. An expired CA turns FINAL without one, since a CRL signed by an expired CA is not trusted.
// Changes go through svc.service so that they publish their events.
func (svc CRLServiceBackend) ReconcileCRLSettings(ctx context.Context, input services.ReconcileCRLSettingsInput) (*models.CRLSettings, error) {
	if err := crlValidate.Struct(input); err != nil {
		return nil, errs.ErrValidateBadRequest
	}

	settings, err := svc.GetCRLSettings(ctx, services.GetCRLSettingsInput{CAID: input.CAID})
	if err != nil || settings.Status == models.CRLSettingsArchived {
		return settings, err
	}

	ca, err := svc.caSDK.GetCAByID(ctx, services.GetCAByIDInput{CAID: input.CAID})
	if errors.Is(err, errs.ErrCANotFound) {
		return svc.service.ArchiveCRLSettings(ctx, services.ArchiveCRLSettingsInput{CAID: input.CAID})
	}
	if err != nil || settings.Status != models.CRLSettingsActive {
		return settings, err
	}

	notAfter := caLatestNotAfter(ca)
	cert := ca.Certificate
	switch {
	case cert.Status == models.StatusExpired, !notAfter.After(time.Now()):
		finalized, _, err := svc.service.FinalizeCRLSettings(ctx, services.FinalizeCRLSettingsInput{CAID: input.CAID})
		return finalized, err
	case cert.Status == models.StatusRevoked && cert.RevocationReason != models.RevocationReason(ocsp.CertificateHold) &&
		(input.RevokedBefore.IsZero() || cert.RevocationTimestamp.Before(input.RevokedBefore)):
		finalized, _, err := svc.service.FinalizeCRLSettings(ctx, services.FinalizeCRLSettingsInput{CAID: input.CAID, FinalCRL: true, FinalCRLNextUpdate: notAfter})
		return finalized, err
	}
	// Active, or on hold: a hold is reversible, so the CA keeps signing CRLs.
	return settings, nil
}

// caLatestNotAfter is the latest notAfter among the certificates of a CA: no certificate of the CA is valid after it,
// so no CRL of the CA needs to be either. Today a CA has a single current certificate.
func caLatestNotAfter(ca *models.CACertificate) time.Time {
	return ca.Certificate.ValidTo
}

// getDistributionPointExtension builds the IDP of the CRL of a CA: the URLs of every certificate it covers. For
// migrated settings those are the new one and the old one (/crl/<ski>) of each VA domain, since RFC 5280 6.3.3 requires
// the IDP to match the CDP of the certificate.
func (svc CRLServiceBackend) getDistributionPointExtension(caID string, legacySKI *string) (*pkix.Extension, error) {
	idpNames := []asn1.RawValue{}
	for _, name := range svc.vaDomains {
		ids := []string{caID}
		if legacySKI != nil {
			ids = append(ids, *legacySKI)
		}
		for _, id := range ids {
			idpNames = append(idpNames, revocation.URIGeneralName(fmt.Sprintf("http://%s/crl/%s", name, url.PathEscape(id))))
		}
	}

	idp, err := revocation.MarshalIssuingDistributionPoint(revocation.IssuingDistributionPoint{
		DistributionPoint: revocation.DistributionPointName{
			FullName: idpNames,
		},
	})
	if err != nil {
		return nil, err
	}

	return &pkix.Extension{
		Id:       revocation.OIDExtensionIssuingDistributionPoint,
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
