package services

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	cmpwfx "github.com/lamassuiot/lamassuiot/backend/v3/pkg/integrations/wfx"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

// cmpCertConfDefaultTTL is the fallback certConf window applied to a phased
// transaction once it is approved (moves PENDING → ISSUED) when the DMS does
// not configure ConfirmationTimeout. Mirrors the controller's cmpTxTTL — the
// post-approval row behaves like any other issued-awaiting-confirmation row.
const cmpCertConfDefaultTTL = 5 * time.Minute

// cmpApprovalMinDeliveryWindow floors the post-approval certConf window. A
// phased-workflow EE is only allowed to poll again after the pollRep
// checkAfter hint (the controller's defaultPollIntervalSeconds, 60s), so a
// ConfirmationTimeout shorter than one poll cycle would let the confirmation
// monitor revoke the just-approved certificate before the device is even
// permitted to ask for it. Two minutes covers a full poll cycle plus transport
// and clock slack; DMSes configuring a longer ConfirmationTimeout are
// unaffected.
const cmpApprovalMinDeliveryWindow = 2 * time.Minute

// GetCMPTransactionRepo exposes the persistent CMP transaction store so that
// the HTTP controller layer can access it without polluting the DMSManagerService
// interface.  Controllers type-assert the service to CMPTransactionStorer.
func (svc *DMSManagerServiceBackend) GetCMPTransactionRepo() storage.CMPTransactionRepo {
	return svc.cmptxStorage
}

// GetCMPWFXReporter exposes the optional WFX reporter used to mirror CMP
// transaction state transitions into WFX jobs.
func (svc *DMSManagerServiceBackend) GetCMPWFXReporter() cmpwfx.CMPReporter {
	return svc.cmpWFXReporter
}

// GetCMPTransactionsByDMS lists CMP transactions belonging to the given DMS,
// honouring the standard pagination/sort/filter parameters. It verifies the
// DMS exists first so callers get a 404 when targeting a bogus ID rather than
// an empty list that could hide a typo. Both in-flight and stale rows are
// included; expiry filtering is intentionally NOT applied at this layer
// (operators want stale rows visible for diagnosis).
func (svc DMSManagerServiceBackend) GetCMPTransactionsByDMS(ctx context.Context, input services.GetCMPTransactionsByDMSInput) (string, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	exists, _, err := svc.dmsStorage.SelectExists(ctx, input.DMSID)
	if err != nil {
		lFunc.Errorf("could not check DMS %s exists: %s", input.DMSID, err)
		return "", err
	}
	if !exists {
		return "", errs.ErrDMSNotFound
	}

	return svc.cmptxStorage.SelectAllByDMS(ctx, input.DMSID, input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters)
}

// ApproveCMPTransaction releases a PENDING phased-workflow transaction: it
// issues the certificate from the stored CSR, flips the row to ISSUED (so the
// EE can fetch it via pollReq), and mirrors the AwaitingApproval → Responded →
// AwaitingCertConf transitions into WFX. On issuance failure the row is moved
// to ISSUE_FAILED so pollReq can surface the reason.
func (svc DMSManagerServiceBackend) ApproveCMPTransaction(ctx context.Context, input services.ApproveCMPTransactionInput) (*models.CMPTransaction, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	if err := dmsValidate.Struct(input); err != nil {
		lFunc.Errorf("ApproveCMPTransaction: invalid input: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	exists, dms, err := svc.dmsStorage.SelectExists(ctx, input.DMSID)
	if err != nil {
		lFunc.Errorf("could not check DMS %s exists: %s", input.DMSID, err)
		return nil, err
	}
	if !exists {
		return nil, errs.ErrDMSNotFound
	}

	tx, ok, err := svc.cmptxStorage.SelectIncludingExpired(ctx, input.TransactionID)
	if err != nil {
		lFunc.Errorf("ApproveCMPTransaction: lookup tx %s: %s", input.TransactionID, err)
		return nil, err
	}
	// Cross-DMS access is treated as not-found so an operator scoped to one DMS
	// cannot probe another DMS's transaction IDs.
	if !ok || tx.DMSID != input.DMSID {
		return nil, errs.ErrCMPTransactionNotFound
	}
	if tx.State != models.CMPTransactionStatePending {
		lFunc.Warnf("ApproveCMPTransaction: tx %s is in state %s, not PENDING", tx.TransactionID, tx.State)
		return nil, errs.ErrCMPTransactionNotPending
	}
	if !tx.ExpiresAt.IsZero() && tx.ExpiresAt.Before(time.Now()) {
		lFunc.Warnf("ApproveCMPTransaction: tx %s expired at %s", tx.TransactionID, tx.ExpiresAt)
		return nil, errs.ErrCMPTransactionNotPending
	}
	if tx.CSR == nil {
		lFunc.Errorf("ApproveCMPTransaction: tx %s has no stored CSR", tx.TransactionID)
		return nil, errs.ErrCMPTransactionNotPending
	}

	csr := (*x509.CertificateRequest)(tx.CSR)
	// Mark the context as pre-authenticated: the original IR/KUR was already
	// authenticated at submission time, so LWCEnroll/LWCReenroll must not
	// re-run client-cert validation (there is no CMP signer in the admin's
	// approval context).
	issuanceCtx := context.WithValue(ctx, core.LamassuContextKeyPreAuthenticated, true)
	// tx.RequestType is already "ir"/"cr"/"p10cr"/"kur"/"ccr" (see
	// cmpTagToString), so it can be forwarded verbatim as the RFC011
	// operation-identity signal.
	issuanceCtx = context.WithValue(issuanceCtx, core.LamassuContextKeyCMPOperation, tx.RequestType)
	var cert *x509.Certificate
	switch {
	case tx.RequestType == "ccr":
		// Cross-certification admin approval: issue directly via svc (not
		// svc.service) since LightweightCMPCrossCertifier is an optional
		// capability, not part of the DMSManagerService interface — mirrors how
		// the CMP controller's direct-workflow ccr path resolves it. The
		// requested validity window is not persisted on the transaction (see
		// deferCCRForApproval), so notBefore/notAfter fall back to
		// CCR.MaximumValidity/profile default here.
		cert, _, err = svc.LWCIssueCrossCertificate(issuanceCtx, input.DMSID, csr, nil, nil)
	case tx.IsReenrollment:
		cert, err = svc.service.LWCReenroll(issuanceCtx, csr, input.DMSID, nil)
	default:
		cert, err = svc.service.LWCEnroll(issuanceCtx, csr, input.DMSID, nil)
	}
	if err != nil {
		lFunc.Errorf("ApproveCMPTransaction: issuance failed for tx %s: %s", tx.TransactionID, err)
		// Keep the existing (approval-window) expiry so the failed row stays
		// visible to the operator rather than being swept on the short certConf
		// schedule.
		updated, updErr := svc.cmptxStorage.UpdateState(ctx, tx.TransactionID, models.CMPTransactionStateIssueFailed, nil, err.Error(), tx.ExpiresAt)
		if updErr != nil {
			lFunc.Warnf("ApproveCMPTransaction: failed to mark tx %s ISSUE_FAILED: %s", tx.TransactionID, updErr)
		} else if !updated {
			// Row vanished between approval and persistence — likely swept by
			// DeleteExpired. Audit signal only; we cannot recover further here.
			lFunc.Warnf("ApproveCMPTransaction: no live row to mark ISSUE_FAILED for tx %s (already expired/deleted)", tx.TransactionID)
		}
		svc.emitApprovalTransition(ctx, lFunc, tx, cmpwfx.CMPStateRejected, "", err.Error())
		return nil, err
	}

	// Re-base the TTL from the long approval window down to the certConf window:
	// post-approval the row behaves exactly like a direct issuance awaiting
	// certConf. With implicit confirmation there is no certConf message — the
	// cert is confirmed the moment the device fetches it via pollReq — so this
	// window simply bounds how long the (actively polling) device has to pick
	// the certificate up.
	confTimeout := time.Duration(dms.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.ConfirmationTimeout)
	if confTimeout <= 0 {
		confTimeout = cmpCertConfDefaultTTL
	}
	if confTimeout < cmpApprovalMinDeliveryWindow {
		confTimeout = cmpApprovalMinDeliveryWindow
	}
	issuedExpiry := time.Now().Add(confTimeout)

	certSerial := helpers.SerialNumberToHexString(cert.SerialNumber)
	updated, updErr := svc.cmptxStorage.UpdateState(ctx, tx.TransactionID, models.CMPTransactionStateIssued, (*models.X509Certificate)(cert), "", issuedExpiry)
	if updErr != nil {
		lFunc.Errorf("ApproveCMPTransaction: failed to mark tx %s ISSUED: %s", tx.TransactionID, updErr)
		return nil, updErr
	}
	if !updated {
		// The certificate has been issued at the CA but the transaction row
		// was already expired or removed. The cert is orphaned in Lamassu's
		// view; surface it as an error so the caller (admin tooling) can
		// reconcile rather than silently dropping the issuance.
		lFunc.Errorf("ApproveCMPTransaction: tx %s row missing/expired when persisting ISSUED state — cert %s is now orphaned", tx.TransactionID, certSerial)
		return nil, fmt.Errorf("CMP transaction %s no longer exists after issuance (cert %s orphaned; investigate cleanup vs approval timing)", tx.TransactionID, certSerial)
	}
	lFunc.Infof("ApproveCMPTransaction: tx %s approved, certificate %s issued", tx.TransactionID, certSerial)

	// Mirror the admin-gated issuance into WFX: AwaitingApproval → Responded
	// (admin) then Responded → AwaitingCertConf (server now awaits the EE's
	// certConf, retrieved alongside the cert via pollReq).
	svc.emitApprovalTransition(ctx, lFunc, tx, cmpwfx.CMPStateResponded, certSerial, "")
	svc.emitApprovalTransition(ctx, lFunc, tx, cmpwfx.CMPStateAwaitingCertConf, certSerial, "")

	// Reflect the issued outcome on the returned row in-memory; these are the
	// only fields UpdateState changed.
	tx.State = models.CMPTransactionStateIssued
	tx.Certificate = (*models.X509Certificate)(cert)
	tx.CertSerialNumber = certSerial
	tx.ExpiresAt = issuedExpiry
	return &tx, nil
}

// RejectCMPTransaction denies a PENDING phased-workflow CMP transaction
// without issuing a certificate: the row moves to ISSUE_FAILED carrying the
// administrator's reason, which pollReq later surfaces as an error PKIMessage
// to the EE. Mirrors ApproveCMPTransaction's validation, scoping, and WFX
// emission semantics.
func (svc DMSManagerServiceBackend) RejectCMPTransaction(ctx context.Context, input services.RejectCMPTransactionInput) (*models.CMPTransaction, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	if err := dmsValidate.Struct(input); err != nil {
		lFunc.Errorf("RejectCMPTransaction: invalid input: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	exists, _, err := svc.dmsStorage.SelectExists(ctx, input.DMSID)
	if err != nil {
		lFunc.Errorf("could not check DMS %s exists: %s", input.DMSID, err)
		return nil, err
	}
	if !exists {
		return nil, errs.ErrDMSNotFound
	}

	tx, ok, err := svc.cmptxStorage.SelectIncludingExpired(ctx, input.TransactionID)
	if err != nil {
		lFunc.Errorf("RejectCMPTransaction: lookup tx %s: %s", input.TransactionID, err)
		return nil, err
	}
	// Cross-DMS access is treated as not-found (same as ApproveCMPTransaction).
	if !ok || tx.DMSID != input.DMSID {
		return nil, errs.ErrCMPTransactionNotFound
	}
	if tx.State != models.CMPTransactionStatePending {
		lFunc.Warnf("RejectCMPTransaction: tx %s is in state %s, not PENDING", tx.TransactionID, tx.State)
		return nil, errs.ErrCMPTransactionNotPending
	}
	if !tx.ExpiresAt.IsZero() && tx.ExpiresAt.Before(time.Now()) {
		lFunc.Warnf("RejectCMPTransaction: tx %s expired at %s", tx.TransactionID, tx.ExpiresAt)
		return nil, errs.ErrCMPTransactionNotPending
	}

	reason := input.Reason
	if reason == "" {
		reason = "transaction rejected by administrator"
	}

	// Keep the existing PENDING TTL on the ISSUE_FAILED row so the operator
	// keeps seeing it until DeleteExpired sweeps it on the same schedule a
	// timed-out approval would have followed.
	updated, updErr := svc.cmptxStorage.UpdateState(ctx, tx.TransactionID, models.CMPTransactionStateIssueFailed, nil, reason, tx.ExpiresAt)
	if updErr != nil {
		lFunc.Errorf("RejectCMPTransaction: failed to mark tx %s ISSUE_FAILED: %s", tx.TransactionID, updErr)
		return nil, updErr
	}
	if !updated {
		lFunc.Errorf("RejectCMPTransaction: tx %s row missing/expired when persisting ISSUE_FAILED state", tx.TransactionID)
		return nil, errs.ErrCMPTransactionNotPending
	}
	lFunc.Infof("RejectCMPTransaction: tx %s rejected (%s)", tx.TransactionID, reason)

	svc.emitApprovalTransition(ctx, lFunc, tx, cmpwfx.CMPStateRejected, "", reason)

	tx.State = models.CMPTransactionStateIssueFailed
	tx.ErrorMessage = reason
	return &tx, nil
}

// emitApprovalTransition pushes one phased-workflow state transition into WFX,
// keyed to the transaction's existing job. No-op when WFX is disabled.
func (svc DMSManagerServiceBackend) emitApprovalTransition(ctx context.Context, lFunc *logrus.Entry, tx models.CMPTransaction, state cmpwfx.CMPState, certSerial, reason string) {
	if svc.cmpWFXReporter == nil {
		return
	}
	if _, err := svc.cmpWFXReporter.Emit(ctx, cmpwfx.CMPTransition{
		TransactionID:     tx.TransactionID,
		DMSID:             tx.DMSID,
		RequestType:       tx.RequestType,
		SubjectCommonName: tx.SubjectCommonName,
		CertSerialNumber:  certSerial,
		State:             state,
		Reason:            reason,
		Workflow:          cmpwfx.CMPWorkflowNamePhased,
	}); err != nil {
		lFunc.WithField("cmpState", state).Warnf("ApproveCMPTransaction: WFX transition export failed: %v", err)
	}
}

func (svc DMSManagerServiceBackend) LWCProtectionCredentials(ctx context.Context, aps string) ([]*x509.Certificate, crypto.Signer, error) {
	exists, dms, err := svc.dmsStorage.SelectExists(ctx, aps)
	if err != nil {
		return nil, nil, fmt.Errorf("could not look up DMS '%s': %w", aps, err)
	}
	if !exists {
		return nil, nil, fmt.Errorf("DMS '%s' not found", aps)
	}

	protectionCertSN := dms.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.ProtectionCertificateSerialNumber
	if protectionCertSN == "" {
		// No protection cert configured: the DMS opts out of response signing.
		// (nil chain, nil signer, nil error) signals "send unprotected response"
		// to the controller — distinct from a true error such as KMS unreachable.
		return nil, nil, nil
	}

	cert, err := svc.caClient.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: protectionCertSN})
	if err != nil {
		return nil, nil, fmt.Errorf("could not get protection certificate '%s': %w", protectionCertSN, err)
	}

	caSigner := NewCertificateSigner(ctx, cert, svc.kmsClient)
	leaf := (*x509.Certificate)(cert.Certificate)

	chain := append([]*x509.Certificate{leaf}, svc.walkCAChain(ctx, cert.IssuerCAMetadata.ID)...)
	return chain, caSigner, nil
}

// walkCAChain returns the issuer CA chain starting at startCAID and walking up
// to the root. Returns an empty slice when startCAID is empty.
// A maximum depth of 10 guards against pathological loops in misconfigured CA
// hierarchies; in practice CA hierarchies are at most a few levels deep.
func (svc DMSManagerServiceBackend) walkCAChain(ctx context.Context, startCAID string) []*x509.Certificate {
	const maxDepth = 10
	chain := make([]*x509.Certificate, 0, maxDepth)
	currentID := startCAID
	visited := make(map[string]struct{}, maxDepth)

	for i := 0; i < maxDepth && currentID != ""; i++ {
		if _, seen := visited[currentID]; seen {
			break
		}
		visited[currentID] = struct{}{}

		ca, err := svc.caClient.GetCAByID(ctx, services.GetCAByIDInput{CAID: currentID})
		if err != nil || ca == nil {
			break
		}
		chain = append(chain, (*x509.Certificate)(ca.Certificate.Certificate))

		// Stop when the CA is self-signed (root) or no parent is recorded.
		if ca.Certificate.IssuerCAMetadata.ID == "" || ca.Certificate.IssuerCAMetadata.ID == currentID {
			break
		}
		currentID = ca.Certificate.IssuerCAMetadata.ID
	}
	return chain
}

// kgaHelperCertValidity is the lifetime of the ephemeral KGA helper
// certificates (signer / KARI originator). They exist only to authenticate a
// single central-key-generation response, so a short window is sufficient.
const kgaHelperCertValidity = time.Hour

// crossCertValidity is the maximum lifetime of a CMP cross-certificate
// (ccr/ccp). The requester's CertTemplate validity is honoured up to this cap:
// a requested notAfter within the window is applied exactly, while a longer
// request is clamped to now + crossCertValidity.
const crossCertValidity = 365 * 24 * time.Hour

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

// trustedRACAIDs returns the CA IDs a trusted PKI management entity's
// protection certificate must chain to for this DMS: the LWCMP client-
// certificate ValidationCAs (the same list enrollment auth uses), plus the
// enrollment CA and any re-enrollment migration CAs. Shared by every
// operation that trusts a certificate asserting the id-kp-cmcRA role
// (revocation-on-behalf-of and the ir/cr raVerified POPO shortcut) so they
// apply one consistent trust boundary.
func trustedRACAIDs(dms *models.DMS) []string {
	candidateCAIDs := append(
		[]string{dms.Settings.EnrollmentSettings.EnrollmentCA},
		dms.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.AuthOptionsMTLS.ValidationCAs...)
	return append(candidateCAIDs, dms.Settings.ReEnrollmentSettings.AdditionalValidationCAs...)
}

// validateTrustedRASigner returns nil only when signer both (a) carries the
// id-kp-cmcRA extendedKeyUsage AND (b) chains to a CA this DMS actually
// trusts (trustedRACAIDs). The EKU alone is a self-issued claim anyone can
// mint into a self-signed certificate — chain validation is what proves the
// certificate is genuine rather than a forgery asserting the role.
//
// Callers that need this trust boundary MUST use this — checking
// CertHasExtKeyUsageOID alone (as the RA-initiated revocation case and the
// raVerified POPO shortcut once did) lets an attacker mint a throwaway
// self-signed certificate carrying the EKU and have it trusted outright.
func (svc DMSManagerServiceBackend) validateTrustedRASigner(ctx context.Context, lFunc *logrus.Entry, dms *models.DMS, signer *x509.Certificate, requireCMCRAEKU bool) error {
	// The id-kp-cmcRA EKU is a self-issued claim on its own; the load-bearing
	// check is always the chain to a DMS-trusted CA below. Whether the EKU is
	// additionally mandatory is caller-controlled (RFC011 RR.TrustedRA.
	// RequireCMCRAEKU for revocation; always required for the enrollment
	// raVerified shortcut).
	if requireCMCRAEKU && !chelpers.CertHasExtKeyUsageOID(signer, chelpers.OidExtKeyUsageCMCRA) {
		return fmt.Errorf("signer does not carry id-kp-cmcRA")
	}
	if _, err := svc.validateCMPSignerAgainstCAs(ctx, lFunc, signer, trustedRACAIDs(dms), false); err != nil {
		return fmt.Errorf("signer does not chain to a DMS-trusted CA: %w", err)
	}
	return nil
}

// LWCValidateRASigner reports whether signer is a certificate this DMS
// trusts as a PKI management entity (RFC 9483 §5.3.2 / §5.2.3.2): it must
// carry id-kp-cmcRA AND chain to a CA the DMS actually trusts. The CMP
// controller uses this to decide whether to honour a raVerified POPO claim —
// EKU presence alone is a self-issued claim anyone can mint, so it must never
// be trusted without the chain check this method performs.
func (svc DMSManagerServiceBackend) LWCValidateRASigner(ctx context.Context, aps string, signer *x509.Certificate) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{ID: aps})
	if err != nil {
		lFunc.Errorf("could not get DMS '%s': %s", aps, err)
		return errs.ErrDMSNotFound
	}

	return svc.validateTrustedRASigner(ctx, lFunc, dms, signer, true)
}

// LWCValidateCCRRequester implements
// services.LightweightCMPCrossCertRequesterValidator: an empty
// CCR.TrustedRequesterCAIDs means unrestricted (any CA satisfying
// CCR.RequireCACertificate may request); a non-empty list requires the
// requester's signer certificate to chain to one of the listed CAs.
func (svc DMSManagerServiceBackend) LWCValidateCCRRequester(ctx context.Context, aps string, signer *x509.Certificate) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{ID: aps})
	if err != nil {
		lFunc.Errorf("could not get DMS '%s': %s", aps, err)
		return errs.ErrDMSNotFound
	}

	trustedCAIDs := dms.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.CCR.TrustedRequesterCAIDs
	if len(trustedCAIDs) == 0 {
		return nil
	}
	if _, err := svc.validateCMPSignerAgainstCAs(ctx, lFunc, signer, trustedCAIDs, false); err != nil {
		return fmt.Errorf("signer does not chain to a CA on CCR.TrustedRequesterCAIDs: %w", err)
	}
	return nil
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
	if ok && tx.IsReenrollment && tx.State == models.CMPTransactionStateConfirmed {
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

// cmpOperationFromContext reads the RFC011 operation-identity signal set by
// the CMP controller (core.LamassuContextKeyCMPOperation) so LWCEnroll — shared
// across ir/cr/p10cr — can apply per-operation settings. Absent or
// unrecognized defaults to "ir", the least-restrictive/backward-compatible
// choice (ir has no allow-list-style fields like CR.AllowedProfileIDs).
func cmpOperationFromContext(ctx context.Context) string {
	if op, ok := ctx.Value(core.LamassuContextKeyCMPOperation).(string); ok {
		switch op {
		case "cr", "p10cr":
			return op
		}
	}
	return "ir"
}

// applyCMPOpRegistrationOverride overrides the DMS-general RegistrationMode /
// EnableReplaceableEnrollment with an ir/p10cr operation's registration_mode /
// existing_device_policy, when configured (non-"inherit"/non-empty). CR has no
// such fields (a cr always targets an already-registered device per its own
// RequireExistingDevice), so callers only invoke this for ir and p10cr.
func applyCMPOpRegistrationOverride(enrollSettings models.EnrollmentSettings, mode models.CMPOpRegistrationMode, policy models.CMPExistingDevicePolicy) models.EnrollmentSettings {
	switch mode {
	case models.CMPOpRegistrationModeJITP:
		enrollSettings.RegistrationMode = models.JITP
	case models.CMPOpRegistrationModePreRegistration:
		enrollSettings.RegistrationMode = models.PreRegistration
	}
	// Only "replace" overrides — it's a genuine per-op opt-in to allow
	// replacement even under a stricter DMS-general policy. "reject" does NOT
	// force EnableReplaceableEnrollment off: unlike registration_mode,
	// CMPExistingDevicePolicy has no "inherit" sentinel and resolveIR/
	// resolveP10CR always concretize an unset value to "reject", so "reject"
	// is indistinguishable from "never configured" — treating it as an
	// override would silently defeat a DMS that explicitly set the general
	// EnableReplaceableEnrollment=true and never touched this per-op field.
	if policy == models.CMPExistingDevicePolicyReplace {
		enrollSettings.EnableReplaceableEnrollment = true
	}
	return enrollSettings
}

// countActiveDeviceCertificates counts the certificates recorded in a device's
// identity slot (across all versions, not just the current ActiveVersion) that
// the CA still reports as non-revoked. Backs CR.MaximumActiveCertificates:
// there is no dedicated storage index for "certs currently held by device X",
// so this walks the slot's version→serial map and checks each serial's live
// CA status. A lookup failure for one serial is logged and skipped rather than
// aborting the whole count, since a stale/pruned serial should not block new
// enrollments indefinitely.
func (svc DMSManagerServiceBackend) countActiveDeviceCertificates(ctx context.Context, lFunc *logrus.Entry, slot *models.Slot[string]) int {
	if slot == nil {
		return 0
	}
	count := 0
	for _, serial := range slot.Secrets {
		cert, err := svc.caClient.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: serial})
		if err != nil {
			lFunc.Warnf("CR.MaximumActiveCertificates: could not check certificate %s status, skipping from count: %s", serial, err)
			continue
		}
		if cert.Status != models.StatusRevoked {
			count++
		}
	}
	return count
}

// resolveCMPIssuanceProfile resolves the issuance profile for an ir/cr/p10cr
// enrollment, honouring the operation's policy_overrides.issuance_profile_id
// (pins a specific profile ahead of the DMS-general one) and allowed_profile_ids
// (an allow-list; empty means unrestricted). ir has no allow-list field, so
// callers pass nil/empty for allowedProfileIDs there.
func (svc DMSManagerServiceBackend) resolveCMPIssuanceProfile(ctx context.Context, lFunc *logrus.Entry, dms *models.DMS, enrollmentCA string, overrideProfileID *string, allowedProfileIDs []string) (*models.IssuanceProfile, error) {
	var profile *models.IssuanceProfile
	var err error
	if overrideProfileID != nil && *overrideProfileID != "" {
		profile, err = svc.caClient.GetIssuanceProfileByID(ctx, services.GetIssuanceProfileByIDInput{ProfileID: *overrideProfileID})
		if err != nil {
			lFunc.Errorf("could not get policy_overrides-pinned issuance profile %s: %s", *overrideProfileID, err)
			return nil, err
		}
	} else {
		profile, err = svc.resolveIssuanceProfile(ctx, lFunc, dms, enrollmentCA)
		if err != nil {
			return nil, err
		}
	}
	if len(allowedProfileIDs) > 0 && !slices.Contains(allowedProfileIDs, profile.ID) {
		lFunc.Errorf("issuance profile %s is not permitted by allowed_profile_ids", profile.ID)
		return nil, fmt.Errorf("issuance profile %s is not permitted for this operation", profile.ID)
	}
	return profile, nil
}

func (svc DMSManagerServiceBackend) LWCEnroll(ctx context.Context, csr *x509.CertificateRequest, aps string, signerCert *x509.Certificate) (*x509.Certificate, error) {
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
	// RFC011: which CMP body (ir/cr/p10cr) drove this call — see
	// cmpOperationFromContext for why "ir" is the safe default.
	cmpOp := cmpOperationFromContext(ctx)

	// Skip authentication when the context signals pre-authenticated (phased
	// workflow: the original IR was validated at submission; the admin approval
	// step has no CMP signer cert in context).
	if preAuth, _ := ctx.Value(core.LamassuContextKeyPreAuthenticated).(bool); !preAuth {
		var signerChain []*x509.Certificate
		if signerCert != nil {
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
		if signerCert != nil {
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

	// RFC011: ir/p10cr may override the DMS-general registration_mode /
	// existing_device_policy; cr has no such fields (see RequireExistingDevice
	// below instead).
	switch cmpOp {
	case "ir":
		enrollSettings = applyCMPOpRegistrationOverride(enrollSettings, cmpOpts.IR.RegistrationMode, cmpOpts.IR.ExistingDevicePolicy)
	case "p10cr":
		enrollSettings = applyCMPOpRegistrationOverride(enrollSettings, cmpOpts.P10CR.RegistrationMode, cmpOpts.P10CR.ExistingDevicePolicy)
	}

	// RFC011: a cr targets a device that already participates in the PKI; when
	// the DMS requires that explicitly, reject a cr against an unregistered
	// device rather than silently falling through to JITP/pre-registration.
	if cmpOp == "cr" && existingDevice == nil && cmpOpts.CR.RequireExistingDevice {
		lFunc.Errorf("aborting cr enrollment. DMS requires an existing device (CR.RequireExistingDevice) but '%s' is not registered", deviceID)
		return nil, fmt.Errorf("certification request requires a pre-existing device identity")
	}

	// Mirror the EST enrollment guards (see Enroll): a device already registered
	// to another DMS is rejected, and re-enrolling an existing device requires
	// EnableReplaceableEnrollment (the superseded cert is then revoked).
	if existingDevice != nil {
		if existingDevice.DMSOwner != dms.ID {
			lFunc.Errorf("aborting enrollment. device '%s' is registered with DMS '%s'", deviceID, existingDevice.DMSOwner)
			return nil, errs.ErrCMPDeviceOwnedByOtherDMS
		}
		if !enrollSettings.EnableReplaceableEnrollment {
			lFunc.Debugf("aborting enrollment. DMS forbids new enrollments. consider switching NewEnrollment option ON in the DMS")
			return nil, fmt.Errorf("forbiddenNewEnrollment")
		}
		lFunc.Debugf("DMS allows replaceable enrollment. Continuing for device '%s'", deviceID)

		// RFC011: for cr, CR.MaximumActiveCertificates caps how many
		// non-revoked certificates the device may hold at once (0 = no cap).
		if cmpOp == "cr" && cmpOpts.CR.MaximumActiveCertificates > 0 {
			active := svc.countActiveDeviceCertificates(ctx, lFunc, existingDevice.IdentitySlot)
			if active >= cmpOpts.CR.MaximumActiveCertificates {
				lFunc.Errorf("aborting cr enrollment. device '%s' already holds %d active certificate(s), at CR.MaximumActiveCertificates=%d", deviceID, active, cmpOpts.CR.MaximumActiveCertificates)
				return nil, fmt.Errorf("device has reached the maximum number of active certificates (%d) for this DMS", cmpOpts.CR.MaximumActiveCertificates)
			}
		}

		// Revoke the superseded active certificate once the new one is issued.
		// General enrollments (ir/p10cr) opt in via
		// ReEnrollmentSettings.RevokeOnReEnrollment, mirroring the KUR path (see
		// LWCReenroll) — without this gate the initial-enroll path revoked
		// unconditionally, inconsistent with KUR and breaking flows that
		// legitimately keep the previous certificate valid (e.g. a reused
		// message-protection cert). A cr instead uses its own
		// CertificateBehavior: "replace" supersedes the prior identity,
		// "additional" keeps it valid (this DMS-model tracks one active
		// identity slot per device, so "additional" cannot mint a second
		// concurrently-active identity — it can only choose not to revoke the
		// previous one).
		revokeSuperseded := dms.Settings.ReEnrollmentSettings.RevokeOnReEnrollment
		if cmpOp == "cr" {
			revokeSuperseded = cmpOpts.CR.CertificateBehavior == models.CMPCertificateBehaviorReplace
		}
		if existingDevice.IdentitySlot != nil && revokeSuperseded {
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

	// RFC011: policy_overrides.issuance_profile_id pins a specific profile
	// ahead of the DMS-general one; allowed_profile_ids (cr/p10cr only)
	// restricts the resolved profile to an allow-list.
	var profileOverride *string
	var allowedProfiles []string
	switch cmpOp {
	case "ir":
		profileOverride = cmpOpts.IR.PolicyOverrides.IssuanceProfileID
	case "cr":
		profileOverride = cmpOpts.CR.PolicyOverrides.IssuanceProfileID
		allowedProfiles = cmpOpts.CR.AllowedProfileIDs
	case "p10cr":
		profileOverride = cmpOpts.P10CR.PolicyOverrides.IssuanceProfileID
		allowedProfiles = cmpOpts.P10CR.AllowedProfileIDs
	}
	issuanceProfile, err := svc.resolveCMPIssuanceProfile(ctx, lFunc, dms, enrollCA, profileOverride, allowedProfiles)
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

func (svc DMSManagerServiceBackend) LWCReenroll(ctx context.Context, csr *x509.CertificateRequest, aps string, signerCert *x509.Certificate) (*x509.Certificate, error) {
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

	// RFC011 KUR key & identity policy: constrain how much the requested
	// certificate may differ from the one being updated.
	kur := dms.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.KUR
	oldX509 := (*x509.Certificate)(currentDeviceCert.Certificate)
	if kur.KeyPolicy == models.CMPKeyPolicyRequireNew &&
		bytes.Equal(csr.RawSubjectPublicKeyInfo, oldX509.RawSubjectPublicKeyInfo) {
		lFunc.Errorf("aborting reenrollment: KUR.KeyPolicy=require_new_key but the request reuses the current public key")
		return nil, fmt.Errorf("key update must present a new key")
	}
	switch kur.IdentityChangePolicy {
	case models.CMPIdentityChangePolicyForbid:
		if !bytes.Equal(csr.RawSubject, oldX509.RawSubject) || sanSignature(csr) != sanSignatureCert(oldX509) {
			lFunc.Errorf("aborting reenrollment: KUR.IdentityChangePolicy=forbid but subject or SAN changed")
			return nil, fmt.Errorf("key update must not change subject or SAN")
		}
	case models.CMPIdentityChangePolicySANOnly:
		if !bytes.Equal(csr.RawSubject, oldX509.RawSubject) {
			lFunc.Errorf("aborting reenrollment: KUR.IdentityChangePolicy=san_only but subject changed")
			return nil, fmt.Errorf("key update must not change subject")
		}
	case models.CMPIdentityChangePolicySubjectAndSAN:
		// Any subject/SAN change permitted.
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
	if signerCert != nil {
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
	ccr := dms.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.CCR

	// RFC011: subject/SAN constraints on the requested cross-certificate. An
	// empty allow-list on either dimension means "no constraint" for that
	// dimension; a non-empty list requires at least one match.
	if rej := validateCCRSubjectConstraints(csr, ccr.SubjectConstraints); rej != "" {
		lFunc.Errorf("aborting cross certification: %s", rej)
		return nil, nil, fmt.Errorf("cross-certificate request violates subject constraints: %s", rej)
	}

	now := time.Now()
	notBefore := now
	if reqNotBefore != nil {
		notBefore = *reqNotBefore
	}
	// RFC011 CCR.MaximumValidity replaces the fixed crossCertValidity cap when
	// configured (non-zero); falls back to the historical default otherwise so
	// DMSs saved before this schema existed keep their prior behavior.
	maxLifetime := crossCertValidity
	if ccr.MaximumValidity > 0 {
		maxLifetime = time.Duration(ccr.MaximumValidity)
	}
	maxNotAfter := now.Add(maxLifetime)
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

// validateCCRSubjectConstraints checks a cross-certification request's subject
// DN and dNSName SANs against RFC011 CCR.SubjectConstraints. An empty
// AllowedDNPatterns / AllowedDNSSuffixes list imposes no constraint on that
// dimension. A DN pattern matches when it is a substring of the request
// subject's RFC 2253 string form; a DNS suffix matches when a SAN
// case-insensitively ends with it. Returns "" when the request satisfies both
// (configured) constraints, otherwise a human-readable rejection reason.
func validateCCRSubjectConstraints(csr *x509.CertificateRequest, c models.CMPSubjectConstraints) string {
	if len(c.AllowedDNPatterns) > 0 {
		subject := csr.Subject.String()
		matched := false
		for _, pattern := range c.AllowedDNPatterns {
			if strings.Contains(subject, pattern) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Sprintf("subject %q does not match any allowed DN pattern", subject)
		}
	}
	if len(c.AllowedDNSSuffixes) > 0 {
		for _, dns := range csr.DNSNames {
			matched := false
			for _, suffix := range c.AllowedDNSSuffixes {
				if strings.HasSuffix(strings.ToLower(dns), strings.ToLower(suffix)) {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Sprintf("SAN %q does not match any allowed DNS suffix", dns)
			}
		}
	}
	return ""
}

// sanSignature / sanSignatureCert produce a canonical, order-independent string
// of a request's / certificate's subjectAltName entries so KUR identity-change
// policy (RFC011) can detect any SAN difference between the requested cert and
// the one being updated.
func sanSignature(csr *x509.CertificateRequest) string {
	parts := make([]string, 0, len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs))
	for _, d := range csr.DNSNames {
		parts = append(parts, "dns:"+d)
	}
	for _, ip := range csr.IPAddresses {
		parts = append(parts, "ip:"+ip.String())
	}
	for _, e := range csr.EmailAddresses {
		parts = append(parts, "email:"+e)
	}
	for _, u := range csr.URIs {
		parts = append(parts, "uri:"+u.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func sanSignatureCert(c *x509.Certificate) string {
	parts := make([]string, 0, len(c.DNSNames)+len(c.IPAddresses)+len(c.EmailAddresses)+len(c.URIs))
	for _, d := range c.DNSNames {
		parts = append(parts, "dns:"+d)
	}
	for _, ip := range c.IPAddresses {
		parts = append(parts, "ip:"+ip.String())
	}
	for _, e := range c.EmailAddresses {
		parts = append(parts, "email:"+e)
	}
	for _, u := range c.URIs {
		parts = append(parts, "uri:"+u.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// cmpRevocationReasonName maps an RFC 5280 CRLReason code to its CMP settings
// allow-list name (RFC011). ok is false for reason codes with no CMP allow-list
// representation (certificateHold, removeFromCRL, privilegeWithdrawn,
// aaCompromise), which are governed elsewhere rather than by RR.AllowedReasons.
func cmpRevocationReasonName(r models.RevocationReason) (models.CMPRevocationReason, bool) {
	switch int(r) {
	case 0:
		return models.CMPRevocationReasonUnspecified, true
	case 1:
		return models.CMPRevocationReasonKeyCompromise, true
	case 2:
		return models.CMPRevocationReasonCACompromise, true
	case 3:
		return models.CMPRevocationReasonAffiliationChanged, true
	case 4:
		return models.CMPRevocationReasonSuperseded, true
	case 5:
		return models.CMPRevocationReasonCessationOfOperation, true
	default:
		return "", false
	}
}

func cmpReasonAllowed(name models.CMPRevocationReason, allowed []models.CMPRevocationReason) bool {
	for _, a := range allowed {
		if a == name {
			return true
		}
	}
	return false
}

func (svc DMSManagerServiceBackend) LWCRevokeCertificate(ctx context.Context, input services.RevokeCertificateInput, signerCert *x509.Certificate) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{
		ID: input.APS,
	})
	if err != nil {
		lFunc.Errorf("aborting revocation. Could not get DMS '%s': %s", input.APS, err)
		return errs.ErrDMSNotFound
	}

	// RFC 9483 §5.3.2: when the rr protection signer is NOT the certificate
	// being revoked, only a trusted PKI management entity may act on another
	// entity's behalf. Trust means BOTH the id-kp-cmcRA extendedKeyUsage AND a
	// chain to one of the DMS validation CAs — the EKU alone is a self-issued
	// claim anyone can mint.
	//
	// The self-revocation case (signer == target) MUST NOT rely solely on the
	// controller's CertTemplate-vs-signer field match: serial/issuer/subject/
	// publicKey there are read straight off the attacker-supplied signer
	// certificate, so a self-signed certificate crafted to assert someone
	// else's (non-secret) serial number and issuer name passes that match
	// trivially without the attacker ever holding the real certificate. The
	// signer MUST also chain to a CA this DMS actually trusts for CMP-issued
	// certificates — that's what proves the certificate is genuine rather
	// than a forgery. Without this, any party who has merely observed a
	// target certificate's serial/issuer (e.g. via CT logs or a TLS
	// handshake) could revoke it.
	rr := dms.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.RR

	if signer := signerCert; signer != nil {
		signerSN := helpers.SerialNumberToHexString(signer.SerialNumber)
		selfRevocation := signerSN == input.SerialNumber

		if !selfRevocation {
			// RFC011: RR.Authorization=self_only forbids a third party (even a
			// trusted RA) from revoking another entity's certificate.
			if rr.Authorization == models.CMPRevocationAuthorizationSelfOnly {
				lFunc.Errorf("aborting revocation of '%s': DMS permits self-revocation only (RR.Authorization=self_only)", input.SerialNumber)
				return errs.ErrDMSEnrollInvalidCert
			}
			if vErr := svc.validateTrustedRASigner(ctx, lFunc, dms, signer, rr.TrustedRA.RequireCMCRAEKU); vErr != nil {
				lFunc.Errorf("aborting revocation of '%s': signer SN=%s is not a trusted PKI management entity: %s",
					input.SerialNumber, signerSN, vErr)
				return errs.ErrDMSEnrollInvalidCert
			}
		} else {
			// Self-revocation of a device's own already-expired certificate is
			// permitted only when RR.AllowExpiredTarget is set (RFC011); the
			// allowExpired flag on chain validation reflects that policy.
			candidateCAIDs := trustedRACAIDs(dms)
			if _, vErr := svc.validateCMPSignerAgainstCAs(ctx, lFunc, signer, candidateCAIDs, rr.AllowExpiredTarget); vErr != nil {
				lFunc.Errorf("aborting revocation of '%s': signer CN=%s does not chain to a DMS-trusted CA: %s",
					input.SerialNumber, signer.Subject.CommonName, vErr)
				return errs.ErrDMSEnrollInvalidCert
			}
		}
		if selfRevocation {
			lFunc.Infof("revocation of '%s' authorized: signer is the certificate's own CA-validated protection cert", input.SerialNumber)
		} else {
			lFunc.Infof("revocation of '%s' authorized for trusted PKI management entity CN=%s (RFC 9483 §5.3.2)",
				input.SerialNumber, signer.Subject.CommonName)
		}
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
		// RFC011: revival (removeFromCRL / un-revoke) is only permitted when the
		// DMS opts in via RR.AllowRevival (default off). Otherwise the request is
		// refused as an unauthorized state transition.
		if !dms.Settings.EnrollmentSettings.EnrollmentOptionsLWCRFC9483.RR.AllowRevival {
			lFunc.Warnf("revive rejected: RR.AllowRevival is disabled for DMS '%s'", input.APS)
			return errs.ErrCertificateStatusTransitionNotAllowed
		}
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

	// RFC011: RR.AllowExpiredTarget gates whether an already-expired certificate
	// may be revoked at all. Status is the authoritative expiry signal (kept
	// current by the expiry monitor) — checked alone, not alongside a raw
	// ValidTo comparison, since that field isn't guaranteed populated on every
	// Certificate value a caller constructs.
	if !rr.AllowExpiredTarget && cert.Status == models.StatusExpired {
		lFunc.Warnf("revocation rejected: certificate '%s' is expired and RR.AllowExpiredTarget is disabled", input.SerialNumber)
		return errs.ErrCertificateStatusTransitionNotAllowed
	}

	// RFC011: RR.AllowedReasons restricts which CRLReason codes the DMS accepts.
	// Only reasons representable in the CMP allow-list are gated; reasons outside
	// that set (e.g. certificateHold) are left to the controller's own validation.
	if name, ok := cmpRevocationReasonName(input.Reason); ok && !cmpReasonAllowed(name, rr.AllowedReasons) {
		lFunc.Warnf("revocation rejected: reason %q is not permitted by RR.AllowedReasons for DMS '%s'", name, input.APS)
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
