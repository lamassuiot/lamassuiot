package services

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	core "github.com/lamassuiot/lamassuiot/core/v3"
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

	// CMP presents the client identity as the signature-based message-protection
	// signer cert (extraCerts[0], RFC 9483 §3.2), present only when the request
	// was protected. The same four auth modes as EST apply, run by the shared
	// authenticator. auth_mode is the single source of truth: selecting
	// CLIENT_CERTIFICATE or the combined mode requires a signer cert, and the
	// controller also derives its wire-level protection requirement from
	// auth_mode (no separate enforce_request_protection knob exists).
	cmpOpts := dms.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483

	// Skip authentication when the context signals pre-authenticated (phased
	// workflow: the original IR was validated at submission; the admin approval
	// step has no CMP signer cert in context).
	if preAuth, _ := ctx.Value(core.LamassuContextKeyPreAuthenticated).(bool); !preAuth {
		var signerChain []*x509.Certificate
		if signerCert := cmpSignerCertFromContext(ctx); signerCert != nil {
			signerChain = []*x509.Certificate{signerCert}
		}
		if err := svc.authenticateEnrollment(ctx, lFunc, cmpOpts.AuthSettings(), signerChain, csr, aps, "enrollment"); err != nil {
			return nil, err
		}
	} else {
		lFunc.Infof("skipping enrollment authentication (pre-authenticated phased transaction)")
	}

	var existingDevice *models.Device
	existingDevice, err = svc.deviceManagerCli.GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: csr.Subject.CommonName})
	if err != nil && err != errs.ErrDeviceNotFound {
		lFunc.Errorf("could not get device '%s': %s", csr.Subject.CommonName, err)
		return nil, err
	}

	enrollSettings := dms.Settings.EnrollmentSettings

	// Mirror the EST enrollment guards (see Enroll): a device already registered
	// to another DMS is rejected, and re-enrolling an existing device requires
	// EnableReplaceableEnrollment (the superseded cert is then revoked).
	if existingDevice != nil {
		if existingDevice.DMSOwner != dms.ID {
			lFunc.Errorf("aborting enrollment. device '%s' is registered with DMS '%s'", csr.Subject.CommonName, existingDevice.DMSOwner)
			return nil, fmt.Errorf("device already registered to another DMS")
		}
		if !enrollSettings.EnableReplaceableEnrollment {
			lFunc.Debugf("aborting enrollment. DMS forbids new enrollments. consider switching NewEnrollment option ON in the DMS")
			return nil, fmt.Errorf("forbiddenNewEnrollment")
		}
		lFunc.Debugf("DMS allows replaceable enrollment. Continuing for device '%s'", csr.Subject.CommonName)
		// Revoke the superseded active certificate once the new one is issued,
		// but only when the DMS opts in via ReEnrollmentSettings.RevokeOnReEnrollment.
		// This mirrors the KUR/re-enrollment path (see LWCReenroll), where the
		// superseded cert is revoked only when that flag is set. Without this
		// gate the initial-enroll path revoked unconditionally, which is
		// inconsistent with KUR and breaks flows that legitimately keep the
		// previous certificate valid (e.g. a reused message-protection cert).
		if existingDevice.IdentitySlot != nil && dms.Settings.ReEnrollmentSettings.RevokeOnReEnrollment {
			supersededSN := existingDevice.IdentitySlot.Secrets[existingDevice.IdentitySlot.ActiveVersion]
			defer func() {
				if _, revErr := svc.caClient.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
					SerialNumber:     supersededSN,
					NewStatus:        models.StatusRevoked,
					RevocationReason: ocsp.Superseded,
				}); revErr != nil {
					lFunc.Warnf("could not revoke superseded certificate %s: %s", supersededSN, revErr)
				} else {
					lFunc.Infof("revoked superseded certificate %s", supersededSN)
				}
			}()
		}
	}

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
	// context — we honour that as "skip validation" here. For the non-cert
	// auth modes (NO_AUTH, EXTERNAL_WEBHOOK) the controller accepts unprotected
	// messages; for the cert modes (CLIENT_CERTIFICATE, combined) the
	// controller already rejected this request at the wire layer per auth_mode,
	// so we never reach this branch without a signer.
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

	// Fetch the target certificate so we can validate the requested state
	// transition before asking the CA to perform it. This lets the CMP
	// controller surface precise PKIFailureInfo bits (certRevoked vs badCertId)
	// per RFC 9483 §4.2 instead of relying on the CA client's error mapping
	// surviving the HTTP boundary.
	cert, err := svc.caClient.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: input.SerialNumber,
	})
	if err != nil {
		lFunc.Errorf("could not load certificate '%s': %s", input.SerialNumber, err)
		return err
	}

	// A removeFromCRL (8) CRLReason is the CMP revive operation (RFC 9483 §4.2):
	// it requests un-revocation rather than revocation.
	revive := input.Reason == models.RevocationReason(ocsp.RemoveFromCRL)
	if revive {
		// Only a currently-revoked certificate can be revived. Anything else
		// (active, expired) is an invalid target → badCertId at the controller.
		if cert.Status != models.StatusRevoked {
			lFunc.Warnf("revive rejected: certificate '%s' is not revoked (status=%s)", input.SerialNumber, cert.Status)
			return errs.ErrCertificateStatusTransitionNotAllowed
		}
		_, err = svc.caClient.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
			SerialNumber: input.SerialNumber,
			NewStatus:    models.StatusActive,
		})
		if err != nil {
			lFunc.Errorf("could not revive certificate '%s': %s", input.SerialNumber, err)
			return err
		}
		return nil
	}

	// Revocation: an already-revoked certificate cannot be revoked again
	// → certRevoked at the controller.
	if cert.Status == models.StatusRevoked {
		lFunc.Warnf("revocation rejected: certificate '%s' is already revoked", input.SerialNumber)
		return errs.ErrCertificateStatusTransitionNotAllowed
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
