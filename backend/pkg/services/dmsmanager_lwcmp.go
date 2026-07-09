package services

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

// kgaHelperCertValidity is the lifetime of the ephemeral KGA helper
// certificates (signer / KARI originator). They exist only to authenticate a
// single central-key-generation response, so a short window is sufficient.
const kgaHelperCertValidity = time.Hour

// crossCertValidity is the maximum lifetime of a CMP cross-certificate
// (ccr/ccp). The requester's CertTemplate validity is honoured up to this cap:
// a requested notAfter within the window is applied exactly, while a longer
// request is clamped to now + crossCertValidity.
const crossCertValidity = 365 * 24 * time.Hour

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

// classifySupersededSigner decides which error a CMP operation gets when its
// protection (signer) certificate is NOT the device's active identity cert.
//
// Two situations produce that mismatch, with different RFC 9483 semantics:
//
//   - The signer was the device's identity but a *confirmed key update* (kur)
//     replaced it. Per §4.1.3 an updated certificate can no longer authenticate
//     enrollment operations → ErrCMPCertSuperseded (PKIFailureInfo certRevoked).
//     Detected by: signer serial present in the identity-slot history at a
//     non-active version AND the transaction that issued the currently active
//     cert being a CONFIRMED re-enrollment.
//
//   - Anything else — a foreign certificate, or a cert superseded by a plain
//     replaceable re-enrollment (which Lamassu policy deliberately keeps
//     usable, see RevokeOnReEnrollment) → ErrCMPSignerNotActive
//     (PKIFailureInfo badRequest).
func (svc DMSManagerServiceBackend) classifySupersededSigner(ctx context.Context, lFunc *logrus.Entry, device *models.Device, signerSN, activeSN string) error {
	if device == nil || device.IdentitySlot == nil {
		return errs.ErrCMPSignerNotActive
	}
	inHistory := false
	for version, sn := range device.IdentitySlot.Secrets {
		if sn == signerSN && version != device.IdentitySlot.ActiveVersion {
			inHistory = true
			break
		}
	}
	if !inHistory {
		return errs.ErrCMPSignerNotActive
	}
	tx, ok, err := svc.cmptxStorage.SelectByCertSerial(ctx, activeSN)
	if err != nil {
		lFunc.Warnf("could not classify superseded signer %s (lookup of active cert %s failed): %s", signerSN, activeSN, err)
		return errs.ErrCMPSignerNotActive
	}
	if ok && tx.IsReenrollment && tx.State == storage.CMPTransactionStateConfirmed {
		lFunc.Warnf("signer cert %s was superseded by confirmed key-update tx %s (active cert %s)", signerSN, tx.TransactionID, activeSN)
		return errs.ErrCMPCertSuperseded
	}
	return errs.ErrCMPSignerNotActive
}

// signerInDeviceHistory reports whether signerSN is a (non-active) certificate
// in the device's identity-slot history — i.e. a genuine past credential of
// this device rather than a foreign certificate. Used to decide whether a KUR
// signed by a superseded-but-not-revoked certificate may proceed.
func signerInDeviceHistory(device *models.Device, signerSN string) bool {
	if device == nil || device.IdentitySlot == nil {
		return false
	}
	for _, sn := range device.IdentitySlot.Secrets {
		if sn == signerSN {
			return true
		}
	}
	return false
}

// rejectStaleCMPSigner enforces the RFC 9483 §4.1.3 usability rules for a CMP
// protection certificate that is a managed device identity:
//
//   - the device has a key-update awaiting confirmation → ErrCMPPendingUpdate
//     (the open transaction must complete or time out first);
//   - the signer was superseded by a confirmed key-update →
//     classifySupersededSigner (ErrCMPCertSuperseded / ErrCMPSignerNotActive).
//
// A signer whose CommonName has no device record (e.g. a bootstrap signer
// certificate) — or that IS the device's active identity with no pending
// update — is fine, and nil is returned.
func (svc DMSManagerServiceBackend) rejectStaleCMPSigner(ctx context.Context, lFunc *logrus.Entry, dmsID string, signerCert *x509.Certificate) error {
	signerCN := signerCert.Subject.CommonName
	signerDevice, err := svc.deviceManagerCli.GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: signerCN})
	if err != nil {
		if err == errs.ErrDeviceNotFound {
			return nil // not a device identity (e.g. bootstrap signer)
		}
		lFunc.Warnf("could not check signer device '%s' (continuing): %s", signerCN, err)
		return nil
	}
	if signerDevice == nil || signerDevice.IdentitySlot == nil || signerDevice.DMSOwner != dmsID {
		return nil
	}

	signerSN := helpers.SerialNumberToHexString(signerCert.SerialNumber)
	pending, err := svc.cmptxStorage.HasUnconfirmedReenrollment(ctx, dmsID, signerSN)
	if err != nil {
		lFunc.Warnf("could not check pending key-update for signer cert '%s' (continuing): %s", signerSN, err)
	} else if pending {
		lFunc.Errorf("aborting operation. signer cert %s has a key-update awaiting confirmation (RFC 9483 §4.1.3)", signerSN)
		return errs.ErrCMPPendingUpdate
	}

	// Abandoned key-update (RFC 9483 §4.1.3, sec-awareness): the signer's
	// previous key-update was issued but never confirmed and has since timed out
	// (the confirmation monitor revoked the unconfirmed cert). Such a device
	// must recover via a new key-update (kur), not an ir/cr — reject the
	// enrollment so it cannot fall back to initialization after abandoning an
	// update. The kur path (LWCReenroll) does not call this helper, so recovery
	// via kur remains possible.
	abandoned, err := svc.cmptxStorage.HasAbandonedReenrollment(ctx, dmsID, signerSN)
	if err != nil {
		lFunc.Warnf("could not check abandoned key-update for signer cert '%s' (continuing): %s", signerSN, err)
	} else if abandoned {
		lFunc.Errorf("aborting enrollment. signer cert %s has an abandoned key-update; a new kur is required (RFC 9483 §4.1.3)", signerSN)
		return errs.ErrCMPAbandonedUpdate
	}

	activeSN := signerDevice.IdentitySlot.Secrets[signerDevice.IdentitySlot.ActiveVersion]
	if signerSN != activeSN {
		if cErr := svc.classifySupersededSigner(ctx, lFunc, signerDevice, signerSN, activeSN); cErr == errs.ErrCMPCertSuperseded {
			lFunc.Errorf("aborting operation. signer cert %s of device '%s' was superseded by a confirmed key-update", signerSN, signerCN)
			return cErr
		}
		// Non-active but not KUR-superseded (e.g. replaced via replaceable
		// re-enrollment): Lamassu policy keeps such certs usable — do not block.
	}
	return nil
}

// deviceIdentityFromCSR returns the identifier Lamassu uses to register/bind
// the device for a CMP enrollment. It is the subject CommonName when present;
// otherwise (RFC 9483 §4.1.1 NULL-DN requests) it falls back to the first
// usable SubjectAltName value — dNSName, then rfc822Name (email), then URI,
// then IP address — so a certificate legitimately issued with an empty subject
// and a SAN still maps to a stable device identity. Returns "" when neither a
// CommonName nor any SAN is available, in which case the caller rejects the
// request.
func deviceIdentityFromCSR(csr *x509.CertificateRequest) string {
	if csr.Subject.CommonName != "" {
		return csr.Subject.CommonName
	}
	if len(csr.DNSNames) > 0 {
		return csr.DNSNames[0]
	}
	if len(csr.EmailAddresses) > 0 {
		return csr.EmailAddresses[0]
	}
	if len(csr.URIs) > 0 {
		return csr.URIs[0].String()
	}
	if len(csr.IPAddresses) > 0 {
		return csr.IPAddresses[0].String()
	}
	return ""
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

		// The signer chain-validates, but it must also still be a *usable*
		// credential under RFC 9483 §4.1.3 when it is a managed device identity:
		//   - while that device has a key-update awaiting certConf, the old cert
		//     must not start new operations (→ badRequest);
		//   - once a key-update is confirmed, the superseded cert can no longer
		//     authenticate at all (→ certRevoked).
		// Certificates that are not device identities (e.g. bootstrap signers)
		// have no device record and pass through untouched.
		if signerCert := cmpSignerCertFromContext(ctx); signerCert != nil {
			if err := svc.rejectStaleCMPSigner(ctx, lFunc, dms.ID, signerCert); err != nil {
				return nil, err
			}
		}
	} else {
		lFunc.Infof("skipping enrollment authentication (pre-authenticated phased transaction)")
	}

	// Device identity: normally the CSR subject CommonName. RFC 9483 §4.1.1
	// allows a NULL-DN subject when a SubjectAltName carries the identity, so
	// when the subject CommonName is empty we derive the device id from the SAN
	// (dNSName/email/URI/IP, in that order). The issued certificate keeps its
	// NULL-DN subject; only Lamassu's internal device identity uses this value.
	deviceID := deviceIdentityFromCSR(csr)
	if deviceID == "" {
		lFunc.Errorf("aborting enrollment. request has neither a subject CommonName nor a usable SubjectAltName")
		return nil, fmt.Errorf("cannot determine device identity: empty subject and no SubjectAltName")
	}

	var existingDevice *models.Device
	existingDevice, err = svc.deviceManagerCli.GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: deviceID})
	if err != nil && err != errs.ErrDeviceNotFound {
		lFunc.Errorf("could not get device '%s': %s", deviceID, err)
		return nil, err
	}

	enrollSettings := dms.Settings.EnrollmentSettings

	// Mirror the EST enrollment guards (see Enroll): a device already registered
	// to another DMS is rejected, and re-enrolling an existing device requires
	// EnableReplaceableEnrollment (the superseded cert is then revoked).
	if existingDevice != nil {
		if existingDevice.DMSOwner != dms.ID {
			lFunc.Errorf("aborting enrollment. device '%s' is registered with DMS '%s'", deviceID, existingDevice.DMSOwner)
			return nil, fmt.Errorf("device already registered to another DMS")
		}
		if !enrollSettings.EnableReplaceableEnrollment {
			lFunc.Debugf("aborting enrollment. DMS forbids new enrollments. consider switching NewEnrollment option ON in the DMS")
			return nil, fmt.Errorf("forbiddenNewEnrollment")
		}
		lFunc.Debugf("DMS allows replaceable enrollment. Continuing for device '%s'", deviceID)
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

	device, err := svc.ensureDeviceRegistered(ctx, lFunc, enrollSettings, dms.ID, deviceID, existingDevice)
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
		DeviceID:                deviceID,
		CertificateSerialNumber: crt.SerialNumber,
		BindMode:                bindMode,
	})
	if err != nil {
		lFunc.Errorf("could not assign certificate to device '%s': %s", deviceID, err)
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

		// RFC 9483 §4.1.3 binding: the signer proves possession of the certificate
		// being updated. Usually that is the device's active identity cert. When it
		// is a different certificate, distinguish the supersession cases:
		//   - superseded by a CONFIRMED key-update → the cert can no longer
		//     authenticate operations (certRevoked); reject.
		//   - a foreign certificate (not in this device's history) → not authorized
		//     to update it; reject (badRequest).
		//   - superseded by a replaceable re-enrollment, still a valid past identity
		//     of this device → Lamassu keeps such certs usable (RevokeOnReEnrollment
		//     is false), so allow the update to proceed against that credential,
		//     matching the tolerance LWCEnroll already applies. This also lets a
		//     shared device identity that churned between operations (e.g. the CMP
		//     compliance suite's single-sender KGA IR then KUR) still update.
		if signerSN != currentDeviceCertSN {
			cErr := svc.classifySupersededSigner(ctx, lFunc, device, signerSN, currentDeviceCertSN)
			if cErr == errs.ErrCMPCertSuperseded || !signerInDeviceHistory(device, signerSN) {
				lFunc.Errorf("aborting reenrollment. CMP signer cert SN=%s does not match device's active cert SN=%s (RFC 9483 §4.1.3): %v",
					signerSN, currentDeviceCertSN, cErr)
				return nil, cErr
			}
			lFunc.Warnf("CMP KUR signer cert SN=%s is not the device's active cert SN=%s but is a usable past identity; proceeding (RFC 9483 §4.1.3)",
				signerSN, currentDeviceCertSN)
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

	// Deferred commit (RFC 9483 §4.1.3): the device's active identity is NOT
	// switched to the new certificate here. Binding the new cert and superseding
	// the previous one happen in LWCConfirmReenrollment, invoked by the CMP
	// controller once the EE confirms (certConf) or immediately when implicit
	// confirmation is negotiated. Until confirmation the previous certificate
	// remains the device's active identity, so an unconfirmed key-update can be
	// rolled back on timeout: the confirmation monitor revokes the (unbound) new
	// cert and the device keeps using the old one. Committing here instead would
	// leave the device pointing at a cert that gets revoked on timeout, breaking
	// the "no update without confirmation" guarantee.

	return (*x509.Certificate)(crt.Certificate), nil
}

// LWCConfirmReenrollment commits a previously issued (deferred) key-update: it
// binds the confirmed certificate as the device's active identity and
// supersedes the previously active certificate. It implements
// services.LightweightCMPConfirmer and is invoked by the CMP controller from
// handleCertConf (explicit confirmation) or right after issuance when implicit
// confirmation is negotiated. See LWCReenroll for the deferral rationale.
func (svc DMSManagerServiceBackend) LWCConfirmReenrollment(ctx context.Context, aps string, certSerialNumber string) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{ID: aps})
	if err != nil {
		lFunc.Errorf("aborting reenrollment confirmation. Could not get DMS '%s': %s", aps, err)
		return errs.ErrDMSNotFound
	}
	reEnrollSettings := dms.Settings.ReEnrollmentSettings

	// Resolve the newly issued (now-confirmed) certificate and the device it
	// belongs to. The device's active identity is still the previous cert
	// because the bind was deferred at issuance.
	newCert, err := svc.caClient.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: certSerialNumber,
	})
	if err != nil {
		lFunc.Errorf("could not get confirmed certificate '%s': %s", certSerialNumber, err)
		return fmt.Errorf("could not get confirmed certificate")
	}

	deviceID := (*x509.Certificate)(newCert.Certificate).Subject.CommonName
	device, err := svc.deviceManagerCli.GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: deviceID})
	if err != nil {
		lFunc.Errorf("could not get device '%s' for reenrollment confirmation: %s", deviceID, err)
		return err
	}

	// Idempotency guard: the commit may be attempted more than once (certConf
	// replay after a lost pkiConf, pollReq redelivery, ...). Once the confirmed
	// cert is already the device's active identity there is nothing left to do —
	// re-running BindIdentityToDevice would add a spurious duplicate slot version.
	if device.IdentitySlot != nil &&
		device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion] == certSerialNumber {
		lFunc.Debugf("key-update for cert %s already committed on device %s (idempotent replay)", certSerialNumber, deviceID)
		return nil
	}

	// Supersede the previously active certificate (if any and distinct from the
	// confirmed one): strip its DMS/monitoring metadata and optionally revoke
	// it, mirroring the pre-deferral behaviour of LWCReenroll. Metadata/revoke
	// failures are logged but do not fail the confirmation — the bind below is
	// what makes the key-update effective.
	if device.IdentitySlot != nil {
		supersededSN := device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion]
		if supersededSN != "" && supersededSN != certSerialNumber {
			if _, mErr := svc.caClient.UpdateCertificateMetadata(ctx, services.UpdateCertificateMetadataInput{
				SerialNumber: supersededSN,
				Patches: chelpers.NewPatchBuilder().
					Remove(chelpers.JSONPointerBuilder(models.DMSAttachedToDeviceKey)).
					Remove(chelpers.JSONPointerBuilder(models.CAMetadataMonitoringExpirationDeltasKey)).
					Build(),
			}); mErr != nil {
				lFunc.Warnf("could not update superseded certificate metadata %s: %s", supersededSN, mErr)
			}

			if reEnrollSettings.RevokeOnReEnrollment {
				supersededCert, gErr := svc.caClient.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
					SerialNumber: supersededSN,
				})
				if gErr == nil && supersededCert.Status == models.StatusActive {
					if _, rErr := svc.caClient.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
						SerialNumber:     supersededSN,
						NewStatus:        models.StatusRevoked,
						RevocationReason: ocsp.Superseded,
					}); rErr != nil {
						lFunc.Warnf("could not revoke superseded certificate %s: %s", supersededSN, rErr)
					}
				}
			}
		}
	}

	if _, err = svc.service.BindIdentityToDevice(ctx, services.BindIdentityToDeviceInput{
		DeviceID:                deviceID,
		CertificateSerialNumber: certSerialNumber,
		BindMode:                models.DeviceEventTypeRenewed,
	}); err != nil {
		lFunc.Errorf("could not bind confirmed certificate '%s' to device '%s': %s", certSerialNumber, deviceID, err)
		return err
	}

	lFunc.Infof("confirmed key-update: bound cert %s as active identity for device %s", certSerialNumber, deviceID)
	return nil
}

// LWCIssueKGAHelperCertificate implements services.LightweightCMPKeyGenerator.
// It issues one of the short-lived helper certificates an RFC 9483 §4.1.6
// central-key-generation response needs (the id-kp-cmKGA signer, or the EC
// KARI originator) from the DMS's enrollment CA, without registering a device
// or binding any identity. The controller owns the corresponding private key
// (generated in the software engine) and passes a self-signed CSR here.
func (svc DMSManagerServiceBackend) LWCIssueKGAHelperCertificate(ctx context.Context, aps string, csr *x509.CertificateRequest, purpose services.KGAHelperPurpose) (*x509.Certificate, []*x509.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{ID: aps})
	if err != nil {
		lFunc.Errorf("aborting KGA helper issuance. Could not get DMS '%s': %s", aps, err)
		return nil, nil, errs.ErrDMSNotFound
	}
	enrollCA := dms.Settings.EnrollmentSettings.EnrollmentCA

	// Helper certs are ephemeral: a short validity keeps them from lingering as
	// usable credentials. The subject comes from the CSR (HonorSubject).
	profile := &models.IssuanceProfile{
		Name:         "CMP KGA helper",
		Validity:     models.Validity{Type: models.Duration, Duration: models.TimeDuration(kgaHelperCertValidity)},
		HonorSubject: true,
		// Profile dictates key/extended-key usage (never the self-signed CSR).
		HonorKeyUsage:          false,
		HonorExtendedKeyUsages: false,
	}
	switch purpose {
	case services.KGAHelperSigner:
		// The KGA signer signs the CMS SignedData and must carry id-kp-cmKGA.
		profile.KeyUsage = models.X509KeyUsage(x509.KeyUsageDigitalSignature)
		profile.ExtraExtendedKeyUsageOIDs = []string{chelpers.OidExtKeyUsageCMKGA.String()}
	case services.KGAHelperKARIOriginator:
		// The KARI originator both signs the CMP response protection (so it lands
		// as extraCerts[0]) and is the ECDH peer, hence keyAgreement.
		profile.KeyUsage = models.X509KeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement)
	default:
		return nil, nil, fmt.Errorf("unknown KGA helper purpose %d", purpose)
	}

	crt, err := svc.caClient.SignCertificate(ctx, services.SignCertificateInput{
		CAID:            enrollCA,
		CertRequest:     (*models.X509CertificateRequest)(csr),
		IssuanceProfile: profile,
	})
	if err != nil {
		lFunc.Errorf("could not issue KGA helper certificate (purpose=%d): %s", purpose, err)
		return nil, nil, err
	}

	leaf := (*x509.Certificate)(crt.Certificate)
	chain := svc.walkCAChain(ctx, crt.IssuerCAMetadata.ID)
	lFunc.Infof("issued ephemeral KGA helper certificate CN=%s SN=%s (purpose=%d)",
		leaf.Subject.CommonName, helpers.SerialNumberToHexString(leaf.SerialNumber), purpose)
	return leaf, chain, nil
}

// LWCIssueCrossCertificate implements services.LightweightCMPCrossCertifier.
// It has the DMS's enrollment CA sign csr (whose subject/public key describe the
// requesting CA per the ccr CertTemplate) and returns the issued
// cross-certificate plus its issuing chain. Cross-certification vouches for
// another CA, so the certificate is issued as a CA certificate (SignAsCA) that
// honours the requested subject.
//
// reqNotBefore / reqNotAfter carry the validity requested in the ccr
// CertTemplate. The requested notBefore is honoured as-is; the requested
// notAfter is honoured up to the profile's maximum cross-cert lifetime
// (crossCertValidity). If the request asks for a longer lifetime than the
// profile allows, issuance is capped at the maximum rather than rejected.
func (svc DMSManagerServiceBackend) LWCIssueCrossCertificate(ctx context.Context, aps string, csr *x509.CertificateRequest, reqNotBefore, reqNotAfter *time.Time) (*x509.Certificate, []*x509.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{ID: aps})
	if err != nil {
		lFunc.Errorf("aborting cross certification. Could not get DMS '%s': %s", aps, err)
		return nil, nil, errs.ErrDMSNotFound
	}
	enrollCA := dms.Settings.EnrollmentSettings.EnrollmentCA

	// Resolve the validity window. notBefore defaults to now; the requested
	// notBefore (which may be in the past, e.g. now-1day) is honoured as-is.
	// notAfter defaults to the profile maximum (now + crossCertValidity); the
	// requested notAfter is honoured only up to that cap — a request for a longer
	// lifetime is clamped to the maximum rather than rejected.
	now := time.Now()
	notBefore := now
	if reqNotBefore != nil {
		notBefore = *reqNotBefore
	}
	maxNotAfter := now.Add(crossCertValidity)
	notAfter := maxNotAfter
	if reqNotAfter != nil && reqNotAfter.Before(maxNotAfter) {
		notAfter = *reqNotAfter
	}

	profile := &models.IssuanceProfile{
		Name:         "CMP Cross Certification",
		Validity:     models.Validity{Type: models.Time, Time: notAfter},
		NotBefore:    &notBefore,
		SignAsCA:     true,
		HonorSubject: true,
		// A cross-certified CA certificate MUST carry a KeyUsage extension with
		// the CA bits (keyCertSign, cRLSign) — RFC 5280 §4.2.1.3 / pkilint's
		// ca_certificate_no_ku_extension. digitalSignature is included so the
		// cross-certified CA can also sign protocol/OCSP responses.
		KeyUsage: models.X509KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature),
	}
	crt, err := svc.caClient.SignCertificate(ctx, services.SignCertificateInput{
		CAID:            enrollCA,
		CertRequest:     (*models.X509CertificateRequest)(csr),
		IssuanceProfile: profile,
	})
	if err != nil {
		lFunc.Errorf("could not issue cross certificate: %s", err)
		return nil, nil, err
	}

	leaf := (*x509.Certificate)(crt.Certificate)
	chain := svc.walkCAChain(ctx, crt.IssuerCAMetadata.ID)
	lFunc.Infof("issued cross certificate CN=%s SN=%s", leaf.Subject.CommonName, helpers.SerialNumberToHexString(leaf.SerialNumber))
	return leaf, chain, nil
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

	// RFC 9483 §4.1.3: while the target certificate has a key-update awaiting
	// certConf, its revocation state must not change — the open transaction has
	// to complete (certConf) or time out first. Otherwise an rr racing an
	// unconfirmed kur could revoke the very credential the device still depends
	// on if the update is abandoned.
	if pending, pErr := svc.cmptxStorage.HasUnconfirmedReenrollment(ctx, input.APS, input.SerialNumber); pErr != nil {
		lFunc.Warnf("could not check pending key-update for certificate '%s' (continuing): %s", input.SerialNumber, pErr)
	} else if pending {
		lFunc.Errorf("aborting revocation of '%s': it has a key-update awaiting confirmation (RFC 9483 §4.1.3)", input.SerialNumber)
		return errs.ErrCMPPendingUpdate
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
