package services

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

// cmpSignerCertFromContext returns the EE certificate the CMP handler stashed
// after successfully verifying signature-based protection on the incoming
// PKIMessage (extraCerts[0] per RFC 9483 §3.2). It returns nil when the
// request was unprotected — the controller only stashes a cert when one
// authenticated the message.
func cmpSignerCertFromContext(ctx context.Context) *x509.Certificate {
	v := ctx.Value(string(identityextractors.IdentityExtractorCMPSignerCertificate))
	if v == nil {
		return nil
	}
	cert, _ := v.(*x509.Certificate)
	return cert
}

// validateCMPSignerAgainstCAs chains signerCert against each CA in candidateCAIDs
// (in order) and returns the first matching CA on success. Each candidate ID is
// resolved via the CA client; unknown or failing IDs are logged and skipped.
// When allowExpired is true the chain check is run with the cert's NotBefore as
// "now", so expiry alone won't fail validation — callers that want to apply a
// stricter expiry policy must enforce it separately.
func (svc DMSManagerServiceBackend) validateCMPSignerAgainstCAs(
	ctx context.Context,
	lFunc *logrus.Entry,
	signerCert *x509.Certificate,
	candidateCAIDs []string,
	allowExpired bool,
) (*x509.Certificate, error) {
	for _, caID := range candidateCAIDs {
		ca, err := svc.caClient.GetCAByID(ctx, services.GetCAByIDInput{CAID: caID})
		if err != nil {
			lFunc.Warnf("could not load validation CA '%s': %s", caID, err)
			continue
		}
		caCert := (*x509.Certificate)(ca.Certificate.Certificate)
		if err := helpers.ValidateCertificate(caCert, signerCert, !allowExpired); err != nil {
			lFunc.Debugf("CMP signer cert SN=%s does not chain to CA '%s' (CN=%s): %s",
				helpers.SerialNumberToHexString(signerCert.SerialNumber), caID, caCert.Subject.CommonName, err)
			continue
		}
		lFunc.Debugf("CMP signer cert SN=%s validated against CA '%s' (CN=%s)",
			helpers.SerialNumberToHexString(signerCert.SerialNumber), caID, caCert.Subject.CommonName)
		return caCert, nil
	}
	return nil, errs.ErrDMSEnrollInvalidCert
}

func (svc DMSManagerServiceBackend) LWCEnroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Debugf("checking if DMS '%s' exists", aps)
	dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{
		ID: aps,
	})
	if err != nil {
		lFunc.Errorf("aborting enrollment. Could not get DMS '%s': %s", aps, err)
		return nil, errs.ErrDMSNotFound
	}

	enrollCA := dms.Settings.EnrollmentSettings.EnrollmentCA
	lFunc = lFunc.WithField("dms", dms.ID)

	// Authenticate the CMP signer cert (extraCerts[0]) against ValidationCAs,
	// mirroring the EST mTLS auth path. When the request was unprotected the
	// controller leaves no cert in the context — we honour that as "skip
	// validation", consistent with the EnforceRequestProtection=false escape
	// hatch. To require validation, operators set EnforceRequestProtection=true
	// and configure ValidationCAs.
	cmpOpts := dms.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483
	if signerCert := cmpSignerCertFromContext(ctx); signerCert != nil {
		lFunc = lFunc.WithField("auth-method", "CMP_SIGNER_CERTIFICATE")
		lFunc = lFunc.WithField("auth-uri", fmt.Sprintf("CN=%s, SN=%s, Issuer=%s",
			signerCert.Subject.CommonName,
			helpers.SerialNumberToHexString(signerCert.SerialNumber),
			signerCert.Issuer.CommonName))

		validationCA, err := svc.validateCMPSignerAgainstCAs(ctx, lFunc, signerCert,
			cmpOpts.AuthOptionsMTLS.ValidationCAs, cmpOpts.AuthOptionsMTLS.AllowExpired)
		if err != nil {
			lFunc.Errorf("aborting CMP enrollment. signer cert not authorized for this DMS: %s", err)
			return nil, errs.ErrDMSEnrollInvalidCert
		}

		couldCheck, isRevoked, err := svc.checkCertificateRevocation(ctx, signerCert, validationCA)
		if err != nil {
			lFunc.Errorf("aborting CMP enrollment. revocation check failed: %s", err)
			return nil, err
		}
		if couldCheck && isRevoked {
			lFunc.Errorf("aborting CMP enrollment. signer certificate is revoked")
			return nil, fmt.Errorf("certificate is revoked")
		}
		if !couldCheck {
			lFunc.Warnf("could not check revocation for signer cert; assuming not revoked")
		}
		lFunc.Infof("CMP signer cert authenticated")
	} else {
		lFunc.Warnf("CMP enrollment received without signature-based protection: ValidationCAs not applied")
	}

	var existingDevice *models.Device
	existingDevice, err = svc.deviceManagerCli.GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: csr.Subject.CommonName})
	if err != nil && err != errs.ErrDeviceNotFound {
		lFunc.Errorf("could not get device '%s': %s", csr.Subject.CommonName, err)
		return nil, err
	}

	enrollSettings := dms.Settings.EnrollmentSettings
	device, err := svc.ensureDeviceRegistered(ctx, lFunc, enrollSettings, dms.ID, csr.Subject.CommonName, existingDevice)
	if err != nil {
		return nil, err
	}

	issuanceProfile, err := svc.resolveIssuanceProfile(ctx, lFunc, dms, enrollCA)
	if err != nil {
		return nil, err
	}

	lFunc.Infof("requesting certificate signature")
	crt, err := svc.caClient.SignCertificate(ctx, services.SignCertificateInput{
		CAID:            enrollCA,
		CertRequest:     (*models.X509CertificateRequest)(csr),
		IssuanceProfile: issuanceProfile,
	})
	if err != nil {
		lFunc.Errorf("could not issue certificate for device: %s", err)
		return nil, err
	}

	bindMode := models.DeviceEventTypeProvisioned
	if device.IdentitySlot != nil {
		bindMode = models.DeviceEventTypeReProvisioned
	}

	_, err = svc.service.BindIdentityToDevice(ctx, services.BindIdentityToDeviceInput{
		DeviceID:                csr.Subject.CommonName,
		CertificateSerialNumber: crt.SerialNumber,
		BindMode:                bindMode,
	})
	if err != nil {
		lFunc.Errorf("could not assign certificate to device '%s': %s", csr.Subject.CommonName, err)
		return nil, err
	}

	return (*x509.Certificate)(crt.Certificate), nil
}

func (svc DMSManagerServiceBackend) LWCReenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Debugf("checking if DMS '%s' exists", aps)
	dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{
		ID: aps,
	})
	if err != nil {
		lFunc.Errorf("aborting reenrollment. Could not get DMS '%s': %s", aps, err)
		return nil, errs.ErrDMSNotFound
	}

	enrollSettings := dms.Settings.EnrollmentSettings
	enrollCA := enrollSettings.EnrollmentCA

	device, err := svc.deviceManagerCli.GetDeviceByID(ctx, services.GetDeviceByIDInput{
		ID: csr.Subject.CommonName,
	})
	if err != nil {
		lFunc.Errorf("could not get device '%s': %s", csr.Subject.CommonName, err)
		return nil, err
	}

	if device.IdentitySlot == nil {
		lFunc.Errorf("device '%s' has no identity slot", csr.Subject.CommonName)
		return nil, fmt.Errorf("device has no identity slot")
	}

	currentDeviceCertSN := device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion]
	currentDeviceCert, err := svc.caClient.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: currentDeviceCertSN,
	})
	if err != nil {
		lFunc.Errorf("could not get device certificate '%s': %s", currentDeviceCertSN, err)
		return nil, fmt.Errorf("could not get device certificate")
	}

	if currentDeviceCert.Status == models.StatusRevoked {
		lFunc.Errorf("aborting reenrollment. certificate %s is revoked", currentDeviceCertSN)
		return nil, fmt.Errorf("revoked certificate")
	}

	// Authenticate the CMP signer cert (extraCerts[0]) for KUR.
	//
	// Per RFC 9483 §4.1.3 the KUR signer cert MUST be the cert being updated,
	// so we enforce signer-cert == device's active identity-slot cert by serial.
	// We then chain-validate the signer against the EnrollmentCA, falling back
	// to ReEnrollmentSettings.AdditionalValidationCAs to support migrations
	// where the current cert was issued by a different CA (same model as EST
	// reenroll). Finally we run the same OCSP/CRL/Lamassu-status revocation
	// check EST does.
	//
	// When the request was unprotected the controller leaves no cert in
	// context — we honour that as "skip validation" so EnforceRequestProtection
	// remains the single switch between protected and unprotected operation.
	reEnrollSettings := dms.Settings.ReEnrollmentSettings
	if signerCert := cmpSignerCertFromContext(ctx); signerCert != nil {
		lFunc = lFunc.WithField("auth-method", "CMP_SIGNER_CERTIFICATE")
		signerSN := helpers.SerialNumberToHexString(signerCert.SerialNumber)
		lFunc = lFunc.WithField("auth-uri", fmt.Sprintf("CN=%s, SN=%s, Issuer=%s",
			signerCert.Subject.CommonName, signerSN, signerCert.Issuer.CommonName))

		// RFC 9483 §4.1.3 binding: signer must equal the cert being updated.
		if signerSN != currentDeviceCertSN {
			lFunc.Errorf("aborting reenrollment. CMP signer cert SN=%s does not match device's active cert SN=%s (RFC 9483 §4.1.3)",
				signerSN, currentDeviceCertSN)
			return nil, fmt.Errorf("CMP signer certificate does not match device's active certificate")
		}

		candidateCAIDs := append([]string{enrollCA}, reEnrollSettings.AdditionalValidationCAs...)
		validationCA, err := svc.validateCMPSignerAgainstCAs(ctx, lFunc, signerCert,
			candidateCAIDs, reEnrollSettings.EnableExpiredRenewal)
		if err != nil {
			lFunc.Errorf("aborting reenrollment. CMP signer cert not authorized: %s", err)
			return nil, errs.ErrDMSEnrollInvalidCert
		}

		couldCheck, isRevoked, err := svc.checkCertificateRevocation(ctx, signerCert, validationCA)
		if err != nil {
			lFunc.Errorf("aborting reenrollment. revocation check failed: %s", err)
			return nil, err
		}
		if couldCheck && isRevoked {
			lFunc.Errorf("aborting reenrollment. signer certificate is revoked")
			return nil, fmt.Errorf("certificate is revoked")
		}
		if !couldCheck {
			lFunc.Warnf("could not check revocation for signer cert; assuming not revoked")
		}
		lFunc.Infof("CMP signer cert authenticated for reenrollment")
	} else {
		lFunc.Warnf("CMP reenrollment received without signature-based protection: ValidationCAs not applied")
	}

	issuanceProfile, err := svc.resolveIssuanceProfile(ctx, lFunc, dms, enrollCA)
	if err != nil {
		return nil, err
	}

	crt, err := svc.caClient.SignCertificate(ctx, services.SignCertificateInput{
		CAID:            enrollCA,
		CertRequest:     (*models.X509CertificateRequest)(csr),
		IssuanceProfile: issuanceProfile,
	})
	if err != nil {
		lFunc.Errorf("could not issue certificate for device '%s': %s", csr.Subject.CommonName, err)
		return nil, err
	}

	_, err = svc.caClient.UpdateCertificateMetadata(ctx, services.UpdateCertificateMetadataInput{
		SerialNumber: currentDeviceCertSN,
		Patches: chelpers.NewPatchBuilder().
			Remove(chelpers.JSONPointerBuilder(models.DMSAttachedToDeviceKey)).
			Remove(chelpers.JSONPointerBuilder(models.CAMetadataMonitoringExpirationDeltasKey)).
			Build(),
	})
	if err != nil {
		lFunc.Errorf("could not update superseded certificate metadata %s: %s", currentDeviceCert.SerialNumber, err)
		return nil, err
	}

	if currentDeviceCert.Status == models.StatusActive && reEnrollSettings.RevokeOnReEnrollment {
		_, err = svc.caClient.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
			SerialNumber:     currentDeviceCertSN,
			NewStatus:        models.StatusRevoked,
			RevocationReason: ocsp.Superseded,
		})
		if err != nil {
			lFunc.Errorf("could not revoke superseded certificate %s: %s", currentDeviceCert.SerialNumber, err)
			return nil, err
		}
	}

	_, err = svc.service.BindIdentityToDevice(ctx, services.BindIdentityToDeviceInput{
		DeviceID:                device.ID,
		CertificateSerialNumber: crt.SerialNumber,
		BindMode:                models.DeviceEventTypeRenewed,
	})
	if err != nil {
		return nil, err
	}

	return (*x509.Certificate)(crt.Certificate), nil
}

func (svc DMSManagerServiceBackend) LWCCACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	return svc.CACerts(ctx, aps)
}

func (svc DMSManagerServiceBackend) LWCRevokeCertificate(ctx context.Context, input services.RevokeCertificateInput) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	_, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{
		ID: input.APS,
	})
	if err != nil {
		lFunc.Errorf("aborting revocation. Could not get DMS '%s': %s", input.APS, err)
		return errs.ErrDMSNotFound
	}

	_, err = svc.caClient.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
		SerialNumber:     input.SerialNumber,
		NewStatus:        models.StatusRevoked,
		RevocationReason: input.Reason,
	})
	if err != nil {
		lFunc.Errorf("could not revoke certificate '%s': %s", input.SerialNumber, err)
		return err
	}

	return nil
}

func (svc DMSManagerServiceBackend) LWCGetEnrollmentOptions(ctx context.Context, aps string) (*services.LWCEnrollmentOptions, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)
	dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{ID: aps})
	if err != nil {
		lFunc.Errorf("LWCGetEnrollmentOptions: could not get DMS '%s': %s", aps, err)
		return nil, err
	}
	opts := dms.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483
	return &opts, nil
}

func (svc DMSManagerServiceBackend) LWCGetRootCACertUpdate(ctx context.Context, input services.GetRootCACertUpdateInput) (*services.RootCACertUpdateOutput, error) {
	// Root CA key rollover is not currently supported; signal no update available.
	return nil, nil
}

func (svc DMSManagerServiceBackend) LWCGetCertReqTemplate(ctx context.Context, input services.GetCertReqTemplateInput) (*services.CertReqTemplateOutput, error) {
	// No CA-mandated template restrictions; clients may use any subject/key.
	return nil, nil
}

func (svc DMSManagerServiceBackend) LWCGetCRL(ctx context.Context, input services.GetCMPCRLInput) (*x509.RevocationList, error) {
	// CRL distribution is handled by the VA/CRL service, not the DMS manager.
	return nil, nil
}
