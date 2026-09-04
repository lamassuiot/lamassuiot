package services

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
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
	if tx.CSR == nil {
		lFunc.Errorf("ApproveCMPTransaction: tx %s has no stored CSR", tx.TransactionID)
		return nil, errs.ErrCMPTransactionNotPending
	}

	// Atomically claim the row (PENDING → APPROVING) before doing anything
	// else. This is the sole guard against concurrent Approve/Reject calls
	// (double-click, client retry, or a race between the two, or with the
	// confirmation monitor's approval-timeout sweep) issuing the same CSR
	// twice or clobbering each other's final state: only the caller that wins
	// this atomic transition proceeds to call the CA. A caller that loses
	// gets a clean "not pending" error instead of silently duplicating
	// issuance (see storage.CMPTransactionRepo.ClaimPending).
	claimedTx, claimed, err := svc.cmptxStorage.ClaimPending(ctx, input.TransactionID)
	if err != nil {
		lFunc.Errorf("ApproveCMPTransaction: claim tx %s: %s", input.TransactionID, err)
		return nil, err
	}
	if !claimed {
		lFunc.Warnf("ApproveCMPTransaction: tx %s is no longer PENDING (state=%s) or has expired; refusing to approve", tx.TransactionID, tx.State)
		return nil, errs.ErrCMPTransactionNotPending
	}
	tx = claimedTx

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
	confTimeout := time.Duration(dms.Settings.CMP.EnrollmentSettings.ConfirmationTimeout)
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

	// Atomically claim the row (PENDING → APPROVING) — see the identical
	// comment in ApproveCMPTransaction. This is what prevents a reject from
	// racing (and clobbering) a concurrent approve that already issued a
	// certificate for this transaction.
	claimedTx, claimed, err := svc.cmptxStorage.ClaimPending(ctx, input.TransactionID)
	if err != nil {
		lFunc.Errorf("RejectCMPTransaction: claim tx %s: %s", input.TransactionID, err)
		return nil, err
	}
	if !claimed {
		lFunc.Warnf("RejectCMPTransaction: tx %s is no longer PENDING (state=%s) or has expired; refusing to reject", tx.TransactionID, tx.State)
		return nil, errs.ErrCMPTransactionNotPending
	}
	tx = claimedTx

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
	principals, _ := ctx.Value(core.LamassuContextKeyMatchedPrincipals).([]string)
	if _, err := svc.cmpWFXReporter.Emit(ctx, cmpwfx.CMPTransition{
		TransactionID:     tx.TransactionID,
		DMSID:             tx.DMSID,
		RequestType:       tx.RequestType,
		SubjectCommonName: tx.SubjectCommonName,
		CertSerialNumber:  certSerial,
		State:             state,
		Reason:            reason,
		Principals:        append([]string(nil), principals...),
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

	protectionCertSN := dms.Settings.CMP.EnrollmentSettings.ProtectionCertificateSerialNumber
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

// dmsCAEntry is one CA a DMS is authoritative for, together with its chain.
type dmsCAEntry struct {
	ID    string
	Cert  *x509.Certificate
	Chain []*x509.Certificate // leaf-first, root last (walkCAChain output)
}

// Root returns the trust anchor at the end of the entry's chain, or nil when the
// chain could not be walked.
func (e dmsCAEntry) Root() *x509.Certificate {
	if len(e.Chain) == 0 {
		return nil
	}
	return e.Chain[len(e.Chain)-1]
}

// dmsKnownCAs returns every CA this DMS is authoritative for: the enrollment CA
// plus every managed CA named in ca_distribution_settings, each with its walked
// chain.
//
// This is the set the discovery support messages resolve an EE's question
// against. Scoping them to the enrollment CA alone is too narrow: caCerts hands
// out the managed CAs' certificates, so an EE can legitimately end up trusting
// one of them and then ask for ITS root update or ITS CRL. The enrollment CA is
// placed first so it wins any ambiguity, and duplicates (a managed CA that is
// also the enrollment CA) are collapsed.
func (svc DMSManagerServiceBackend) dmsKnownCAs(ctx context.Context, dms *models.DMS) []dmsCAEntry {
	ids := make([]string, 0, 1+len(dms.Settings.CMP.CADistributionSettings.ManagedCAs))
	if enrollCA := dms.Settings.CMP.EnrollmentSettings.EnrollmentCA; enrollCA != "" {
		ids = append(ids, enrollCA)
	}
	ids = append(ids, dms.Settings.CMP.CADistributionSettings.ManagedCAs...)

	entries := make([]dmsCAEntry, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if _, dup := seen[id]; dup || id == "" {
			continue
		}
		seen[id] = struct{}{}

		chain := svc.walkCAChain(ctx, id)
		if len(chain) == 0 {
			continue
		}
		entries = append(entries, dmsCAEntry{ID: id, Cert: chain[0], Chain: chain})
	}
	return entries
}

// findKnownCABySubject returns the DMS CA whose certificate subject matches
// rawDN byte-for-byte. Comparison is on the raw DER of the RDNSequence rather
// than a rendered DN string, so it is immune to the ordering, escaping and
// string-type differences that make textual DN comparison unreliable.
func findKnownCABySubject(entries []dmsCAEntry, rawDN []byte) *dmsCAEntry {
	for i := range entries {
		if bytes.Equal(entries[i].Cert.RawSubject, rawDN) {
			return &entries[i]
		}
	}
	return nil
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
		[]string{dms.Settings.CMP.EnrollmentSettings.EnrollmentCA},
		dms.Settings.CMP.EnrollmentSettings.AuthOptionsMTLS.ValidationCAs...)
	return append(candidateCAIDs, dms.Settings.CMP.ReEnrollmentSettings.AdditionalValidationCAs...)
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
//
// validationCAIDs narrows the chain-validation scope (RFC011
// RR.TrustedRA.ValidationCAIDs): when non-empty the signer must chain to one of
// exactly those CAs, which is how an operator restricts revocation-capable RAs
// to a subset of the DMS's trust. Empty means "no narrowing" and falls back to
// the DMS-wide trustedRACAIDs boundary. Callers with no per-operation scope to
// apply (e.g. the raVerified enrollment shortcut) pass nil.
func (svc DMSManagerServiceBackend) validateTrustedRASigner(ctx context.Context, lFunc *logrus.Entry, dms *models.DMS, signer *x509.Certificate, requireCMCRAEKU bool, validationCAIDs []string) error {
	// The id-kp-cmcRA EKU is a self-issued claim on its own; the load-bearing
	// check is always the chain to a DMS-trusted CA below. Whether the EKU is
	// additionally mandatory is caller-controlled (RFC011 RR.TrustedRA.
	// RequireCMCRAEKU for revocation; always required for the enrollment
	// raVerified shortcut).
	if requireCMCRAEKU && !chelpers.CertHasExtKeyUsageOID(signer, chelpers.OidExtKeyUsageCMCRA) {
		return fmt.Errorf("signer does not carry id-kp-cmcRA")
	}
	candidateCAIDs := validationCAIDs
	scope := "RR.TrustedRA.ValidationCAIDs"
	if len(candidateCAIDs) == 0 {
		candidateCAIDs = trustedRACAIDs(dms)
		scope = "DMS-wide trust boundary"
	}
	if _, err := svc.validateCMPSignerAgainstCAs(ctx, lFunc, signer, candidateCAIDs, false); err != nil {
		return fmt.Errorf("signer does not chain to a trusted CA (%s): %w", scope, err)
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

	// nil scope: the raVerified enrollment shortcut has no per-operation CA
	// allow-list of its own, so the DMS-wide trust boundary applies.
	return svc.validateTrustedRASigner(ctx, lFunc, dms, signer, true, nil)
}

// LWCValidateCCRRequester implements
// services.LightweightCMPCrossCertRequesterValidator: CCR.RequesterMode=Any
// (the default) is unrestricted — any CA satisfying CCR.RequireCACertificate
// may request. CCR.RequesterMode=Restricted requires the requester's signer
// certificate to chain to a CA on CCR.TrustedRequesterCAIDs; an empty list in
// Restricted mode authorizes no one (a deliberate deny-all, not a fallback
// to unrestricted).
func (svc DMSManagerServiceBackend) LWCValidateCCRRequester(ctx context.Context, aps string, signer *x509.Certificate) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{ID: aps})
	if err != nil {
		lFunc.Errorf("could not get DMS '%s': %s", aps, err)
		return errs.ErrDMSNotFound
	}

	ccr := dms.Settings.CMP.EnrollmentSettings.CCR
	if ccr.RequesterMode != models.CMPCCRRequesterModeRestricted {
		return nil
	}
	if len(ccr.TrustedRequesterCAIDs) == 0 {
		return fmt.Errorf("CCR.RequesterMode is restricted but CCR.TrustedRequesterCAIDs is empty: no CA is authorized to request cross-certification")
	}
	if _, err := svc.validateCMPSignerAgainstCAs(ctx, lFunc, signer, ccr.TrustedRequesterCAIDs, false); err != nil {
		return fmt.Errorf("signer does not chain to a CA on CCR.TrustedRequesterCAIDs: %w", err)
	}
	return nil
}

// LWCValidateKGARecipient implements LightweightCMPKGARecipientValidator: it
// chain-validates the certificate a central-key-generation response would
// encrypt the generated private key to. Unlike the general enrollment
// signer check (authenticateEnrollment, gated by AuthMode and skipped
// entirely under NO_AUTH), this validation is unconditional — CKG hands over
// live key material, so an operator that left AuthMode permissive for
// ordinary enrollment must not thereby also make the RA generate and encrypt
// a private key to an arbitrary, unvalidated self-signed certificate.
func (svc DMSManagerServiceBackend) LWCValidateKGARecipient(ctx context.Context, aps string, recipient *x509.Certificate) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{ID: aps})
	if err != nil {
		lFunc.Errorf("could not get DMS '%s': %s", aps, err)
		return errs.ErrDMSNotFound
	}
	if recipient == nil {
		return fmt.Errorf("central key generation requires a recipient certificate")
	}

	cmpOpts := dms.Settings.CMP.EnrollmentSettings
	candidateCAIDs := cmpOpts.CKGTrustedEncryptionCAs
	if len(candidateCAIDs) == 0 {
		// No explicit CKG trust boundary configured: fall back to the DMS's
		// general CMP trust boundary rather than accepting any certificate
		// unconditionally (see the field doc on CKGTrustedEncryptionCAs).
		candidateCAIDs = trustedRACAIDs(dms)
	}
	if _, err := svc.validateCMPSignerAgainstCAs(ctx, lFunc, recipient, candidateCAIDs, false); err != nil {
		return fmt.Errorf("CKG recipient certificate does not chain to a trusted CA: %w", err)
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

// enrollmentReusesCertificateKey reports whether csr carries the same public key
// as the certificate with the given serial number. Used to apply the
// require_new_key policy to enrollments that replace an existing identity.
//
// A certificate that cannot be loaded or parsed yields an error rather than
// "false": silently treating an unreadable certificate as "different key" would
// turn a lookup failure into a policy bypass.
func (svc DMSManagerServiceBackend) enrollmentReusesCertificateKey(ctx context.Context, lFunc *logrus.Entry, csr *x509.CertificateRequest, certSerial string) (bool, error) {
	current, err := svc.caClient.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: certSerial,
	})
	if err != nil {
		lFunc.Errorf("could not load active certificate '%s' to apply KUR.KeyPolicy: %s", certSerial, err)
		return false, err
	}
	if current.Certificate == nil {
		lFunc.Errorf("active certificate '%s' carries no parsed certificate; cannot apply KUR.KeyPolicy", certSerial)
		return false, fmt.Errorf("could not read active certificate to apply the key-update policy")
	}
	currentX509 := (*x509.Certificate)(current.Certificate)
	return bytes.Equal(csr.RawSubjectPublicKeyInfo, currentX509.RawSubjectPublicKeyInfo), nil
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

	enrollCA := dms.Settings.CMP.EnrollmentSettings.EnrollmentCA
	lFunc = lFunc.WithField("dms", dms.ID)

	// CMP presents the client identity as the signature-based message-protection
	// signer cert (extraCerts[0], RFC 9483 §3.2), present only when the request
	// was protected. The same four auth modes as EST apply, run by the shared
	// authenticator. auth_mode is the single source of truth: selecting
	// CLIENT_CERTIFICATE or the combined mode requires a signer cert, and the
	// controller also derives its wire-level protection requirement from
	// auth_mode (no separate enforce_request_protection knob exists).
	cmpOpts := dms.Settings.CMP.EnrollmentSettings
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

	enrollSettings := dms.Settings.CMP.EnrollmentSettings.CommonEnrollmentSettings

	// RFC011: a cr targets a device that already participates in the PKI; when
	// the DMS requires that explicitly, reject a cr against an unregistered
	// device rather than silently falling through to JITP/pre-registration.
	if cmpOp == "cr" && existingDevice == nil && cmpOpts.CR.RequireExistingDevice {
		lFunc.Errorf("aborting cr enrollment. DMS requires an existing device (CR.RequireExistingDevice) but '%s' is not registered", deviceID)
		return nil, fmt.Errorf("certification request requires a pre-existing device identity")
	}

	// supersededCertToRevoke, when non-empty, is the serial number of the
	// device's current certificate to revoke once (and only once) the new
	// certificate has actually been issued and bound — see the comment below
	// on why this is not a defer.
	var supersededCertToRevoke string

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

		// Revoke the superseded active certificate once the new one is issued
		// AND bound to the device — NOT merely once we decide to attempt
		// enrollment. General enrollments (ir/p10cr) opt in via
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
		//
		// This is intentionally NOT a defer registered here: a defer fires on
		// every return path, including the several enrollment-failure returns
		// between this point and the end of the function (profile resolution,
		// SignCertificate, BindIdentityToDevice) — which would revoke the
		// device's still-valid, still-working certificate while reporting the
		// enrollment itself as failed, leaving the device with no valid
		// certificate at all. supersededCertToRevoke is only acted on after
		// the new certificate is issued and bound, at the bottom of this
		// function.
		revokeSuperseded := dms.Settings.CMP.ReEnrollmentSettings.RevokeOnReEnrollment
		if cmpOp == "cr" {
			revokeSuperseded = cmpOpts.CR.CertificateBehavior == models.CMPCertificateBehaviorReplace
		}
		if existingDevice.IdentitySlot != nil && revokeSuperseded {
			supersededCertToRevoke = existingDevice.IdentitySlot.Secrets[existingDevice.IdentitySlot.ActiveVersion]
		}

		// RFC011 KUR.KeyPolicy=require_new_key was enforced only in LWCReenroll
		// (kur), leaving a bypass: an ir/cr/p10cr that REPLACES the device's active
		// certificate is functionally a key update, so a device could renew on the
		// same key simply by choosing cr-with-replace over kur and the policy would
		// never be consulted. Applied here only when this enrollment actually
		// supersedes the previous identity — an "additional" certificate updates
		// nothing, so the key-update policy has no say over it.
		if supersededCertToRevoke != "" &&
			cmpOpts.KUR.KeyPolicy == models.CMPKeyPolicyRequireNew {
			reused, keyErr := svc.enrollmentReusesCertificateKey(ctx, lFunc, csr, supersededCertToRevoke)
			if keyErr != nil {
				return nil, keyErr
			}
			if reused {
				lFunc.Errorf("aborting %s enrollment for device '%s': KUR.KeyPolicy=require_new_key but the request replaces the active certificate with the same public key", cmpOp, deviceID)
				return nil, fmt.Errorf("key update must present a new key")
			}
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
	// CR.MaximumActiveCertificates was checked above against a snapshot of
	// the device fetched at the top of this call — enough to reject the
	// common case fast, but not race-free: two concurrent cr requests for the
	// same device could both read "under the cap" before either has issued.
	// When the cap is actually configured, re-run the count against a FRESH
	// device fetch immediately before SignCertificate, inside a per-device
	// lock, so only one concurrent caller can observe "under the cap" and
	// proceed — the other sees the freshly-issued certificate in its recount
	// and is rejected. ir/p10cr and cr-without-a-cap skip the lock entirely.
	needsMaxActiveCertsRecheck := cmpOp == "cr" && cmpOpts.CR.MaximumActiveCertificates > 0
	var crt *models.Certificate
	signCertificate := func(ctx context.Context) error {
		if needsMaxActiveCertsRecheck {
			fresh, ferr := svc.deviceManagerCli.GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: deviceID})
			if ferr != nil {
				return ferr
			}
			active := svc.countActiveDeviceCertificates(ctx, lFunc, fresh.IdentitySlot)
			if active >= cmpOpts.CR.MaximumActiveCertificates {
				return fmt.Errorf("device has reached the maximum number of active certificates (%d) for this DMS", cmpOpts.CR.MaximumActiveCertificates)
			}
		}
		var signErr error
		crt, signErr = svc.caClient.SignCertificate(ctx, services.SignCertificateInput{
			CAID:            enrollCA,
			CertRequest:     (*models.X509CertificateRequest)(csr),
			IssuanceProfile: issuanceProfile,
		})
		return signErr
	}
	if needsMaxActiveCertsRecheck {
		err = svc.cmptxStorage.WithDeviceLock(ctx, deviceID, signCertificate)
	} else {
		err = signCertificate(ctx)
	}
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

	// Only now — after the new certificate is issued AND bound as the
	// device's active identity — revoke the superseded one. Doing this any
	// earlier (e.g. via a defer registered before the failure-prone steps
	// above) risks revoking the device's still-working certificate while the
	// enrollment attempt that was supposed to replace it has itself failed.
	if supersededCertToRevoke != "" {
		if _, revErr := svc.caClient.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
			SerialNumber:     supersededCertToRevoke,
			NewStatus:        models.StatusRevoked,
			RevocationReason: ocsp.Superseded,
		}); revErr != nil {
			lFunc.Warnf("could not revoke superseded certificate %s: %s", supersededCertToRevoke, revErr)
		} else {
			lFunc.Infof("revoked superseded certificate %s", supersededCertToRevoke)
		}
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

	enrollSettings := dms.Settings.CMP.EnrollmentSettings
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
	kur := dms.Settings.CMP.EnrollmentSettings.KUR
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
	// The wire layer (HandleCMP / handleNestedAddedProtection) now forces
	// signature-based protection on every kur regardless of auth_mode — the
	// signer cert IS the kur's proof of possession (RFC 9483 §4.1.3), so an
	// unprotected kur must never reach here. The one legitimate exception is
	// the phased (admin-approval) workflow: ApproveCMPTransaction calls
	// LWCReenroll with signerCert=nil because the original kur was already
	// authenticated at submission time, and marks the context accordingly.
	// Any other nil-signer arrival is a defect upstream, not a request to
	// honour — fail closed rather than silently skipping ValidationCAs.
	reEnrollSettings := dms.Settings.CMP.ReEnrollmentSettings
	if signerCert == nil {
		if preAuth, _ := ctx.Value(core.LamassuContextKeyPreAuthenticated).(bool); !preAuth {
			lFunc.Errorf("aborting reenrollment. kur reached the service layer without signature-based protection and without pre-authentication (RFC 9483 §4.1.3)")
			return nil, errs.ErrDMSEnrollInvalidCert
		}
		lFunc.Infof("skipping KUR signer validation (pre-authenticated phased transaction)")
	} else {
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
	reEnrollSettings := dms.Settings.CMP.ReEnrollmentSettings

	// Resolve the newly issued (now-confirmed) certificate and the device it
	// belongs to. The device's active identity is still the previous cert
	// because the bind was deferred at issuance.
	if certSerialNumber == "" {
		// A blank serial turns "/v1/certificates/" into "/v1/certificates/" →
		// (trailing-slash redirect) → the CA's list endpoint instead of a
		// single-certificate lookup, which decodes into a zero-value
		// *models.Certificate with no error. Reject explicitly here instead of
		// letting that zero value reach the dereference below.
		lFunc.Errorf("aborting reenrollment confirmation: empty certificate serial number")
		return fmt.Errorf("cannot commit reenrollment: empty certificate serial number")
	}
	newCert, err := svc.caClient.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: certSerialNumber,
	})
	if err != nil {
		lFunc.Errorf("could not get confirmed certificate '%s': %s", certSerialNumber, err)
		return fmt.Errorf("could not get confirmed certificate")
	}
	if newCert == nil || newCert.Certificate == nil {
		lFunc.Errorf("confirmed certificate '%s' lookup returned no certificate", certSerialNumber)
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
	enrollCA := dms.Settings.CMP.EnrollmentSettings.EnrollmentCA

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
	enrollCA := dms.Settings.CMP.EnrollmentSettings.EnrollmentCA

	// Resolve the validity window. notBefore defaults to now; the requested
	// notBefore (which may be in the past, e.g. now-1day) is honoured as-is.
	// notAfter defaults to the profile maximum (now + crossCertValidity); the
	// requested notAfter is honoured only up to that cap — a request for a longer
	// lifetime is clamped to the maximum rather than rejected.
	ccr := dms.Settings.CMP.EnrollmentSettings.CCR

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
// allow-list name (RFC011). A code with no mapping is NOT gated by
// RR.AllowedReasons, because the caller's check reads
// `if name, ok := ...; ok && !allowed(name)`.
//
// Two codes are deliberately left unmapped, and both belong to the
// suspend/resume lifecycle rather than to permanent revocation:
//
//   - certificateHold (6) suspends a certificate. It is the only revocation
//     reason that can be reversed, and RR.AllowRevival's hold-release path is
//     reachable only for certificates placed on hold — so hold and its release
//     are one feature, gated by AllowRevival, not two entries in a list of
//     permanent revocation reasons. RFC 9483 conformance also requires a CA to
//     accept it: the suite's revive tests place a certificate on hold first, so
//     gating it here breaks the entire revive flow. Gating it would additionally
//     be unfixable by changing defaults — resolveRR only fills a "fresh" RR
//     block, so every DMS whose allowed_reasons was ever configured would need a
//     manual config migration to keep working.
//   - removeFromCRL (8) is the hold *release* itself, governed by AllowRevival.
//
// Every OTHER reason an EE can put on the wire must map to a name here, or the
// operator's allow-list is silently bypassed. privilegeWithdrawn (9) and
// aaCompromise (10) are permanent revocation reasons with no other gate and used
// to fall in exactly that hole.
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
	case 9:
		return models.CMPRevocationReasonPrivilegeWithdrawn, true
	case 10:
		return models.CMPRevocationReasonAACompromise, true
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

// cmpCertificateOwnerDMS resolves which DMS owns the certificate being revoked,
// from whichever record can establish it:
//
//  1. The device registry, keyed by the certificate's subject CommonName (the
//     device ID). This covers anything enrolled through a DMS, over CMP or EST.
//  2. The CMP transaction store, keyed by the certificate's serial number. This
//     covers certificates whose subject is not a device ID — a p10cr with an
//     arbitrary subject, or a ccr cross-certificate naming a CA — which the
//     device registry can never resolve.
//
// ownerKnown is false when neither record identifies an owner; callers must treat
// that as "authority not established", never as "owned by us". A transport or
// lookup failure (as opposed to a clean not-found) is returned as an error rather
// than collapsed into ownerKnown=false, so an unavailable device manager cannot
// silently widen who may revoke what.
func (svc DMSManagerServiceBackend) cmpCertificateOwnerDMS(ctx context.Context, lFunc *logrus.Entry, cert *models.Certificate, serialNumber string) (owner string, ownerKnown bool, err error) {
	if cert.Subject.CommonName != "" && svc.deviceManagerCli != nil {
		device, devErr := svc.deviceManagerCli.GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: cert.Subject.CommonName})
		switch {
		case devErr == nil:
			return device.DMSOwner, true, nil
		case !errors.Is(devErr, errs.ErrDeviceNotFound):
			lFunc.Errorf("could not check device ownership for certificate '%s': %s", serialNumber, devErr)
			return "", false, devErr
		}
		// ErrDeviceNotFound: the CN is not a registered device. Fall through to
		// the transaction store rather than concluding anything from its absence.
	}

	if svc.cmptxStorage != nil {
		tx, found, txErr := svc.cmptxStorage.SelectByCertSerial(ctx, serialNumber)
		if txErr != nil {
			lFunc.Errorf("could not check CMP transaction ownership for certificate '%s': %s", serialNumber, txErr)
			return "", false, txErr
		}
		if found && tx.DMSID != "" {
			return tx.DMSID, true, nil
		}
	}

	return "", false, nil
}

func (svc DMSManagerServiceBackend) LWCRevokeCertificate(ctx context.Context, input services.RevokeCertificateInput, signerCert *x509.Certificate) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	// An rr is ALWAYS signature-protected (RFC 9483 §4.2), so a nil signer means
	// there is nothing to authorize against and the request must be refused.
	// The controller already guarantees this — requireProtectionForBody returns
	// true unconditionally for BodyTagRR, so an unprotected rr never reaches
	// here — but this method must not DEPEND on that: every authorization check
	// below (RR.Authorization, trusted-RA validation, signer chain validation)
	// lives inside a `signer != nil` block, which SKIPS rather than denies when
	// the signer is absent. That shape fails open, so if the always-protected
	// invariant were ever relaxed upstream — a new auth_mode branch, another
	// caller of this service method — the whole authorization stack would
	// silently disappear with no error and no failing test. Enforcing the
	// precondition here keeps the invariant local to the function that depends
	// on it.
	if signerCert == nil {
		lFunc.Errorf("aborting revocation of '%s': rr carries no protection certificate to authorize against (RFC 9483 §4.2)", input.SerialNumber)
		return errs.ErrDMSEnrollInvalidCert
	}

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
	rr := dms.Settings.CMP.EnrollmentSettings.RR

	// Hoisted out of the signer block below so the device-ownership check further
	// down can distinguish "the requester is revoking its own certificate" from
	// "a third party is revoking someone else's".
	selfRevocation := false

	// signerCert is guaranteed non-nil by the precondition at the top of this
	// method; the guard is kept only so the block cannot fail open again if that
	// precondition is ever moved or removed.
	if signer := signerCert; signer != nil {
		signerSN := helpers.SerialNumberToHexString(signer.SerialNumber)
		selfRevocation = signerSN == input.SerialNumber

		if !selfRevocation {
			// RFC011: RR.Authorization=self_only forbids a third party (even a
			// trusted RA) from revoking another entity's certificate.
			if rr.Authorization == models.CMPRevocationAuthorizationSelfOnly {
				lFunc.Errorf("aborting revocation of '%s': DMS permits self-revocation only (RR.Authorization=self_only)", input.SerialNumber)
				return errs.ErrDMSEnrollInvalidCert
			}
			if vErr := svc.validateTrustedRASigner(ctx, lFunc, dms, signer, rr.TrustedRA.RequireCMCRAEKU, rr.TrustedRA.ValidationCAIDs); vErr != nil {
				lFunc.Errorf("aborting revocation of '%s': signer SN=%s is not a trusted PKI management entity: %s",
					input.SerialNumber, signerSN, vErr)
				return errs.ErrDMSEnrollInvalidCert
			}
		} else {
			candidateCAIDs := trustedRACAIDs(dms)
			if _, vErr := svc.validateCMPSignerAgainstCAs(ctx, lFunc, signer, candidateCAIDs, false); vErr != nil {
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

	// RFC 9483 §5.3.2 / RFC010 story 20: the certificate being revoked MUST
	// belong to a device managed by the DMS the rr was addressed to. Without
	// this, a trusted-RA-authorized signer for one DMS could revoke an
	// arbitrary certificate belonging to a device under a completely
	// unrelated DMS merely by naming its serial number — entirely bypassing
	// that other DMS's own RR policy (authorization, AllowedReasons, ...).
	// Scoped by the certificate's owning device
	// rather than by CA membership alone, because two DMSes can legitimately
	// share the same EnrollmentCA (chain-validating the signer against this
	// DMS's trusted CAs, as done above, does not prove the *target*
	// certificate belongs to this DMS too).
	// This check used to fail OPEN in two ways: it was skipped entirely for a
	// certificate with an empty subject CommonName, and — even when the CN was
	// present — it only rejected when the CN actually resolved to a device record,
	// so a CN naming no registered device (a p10cr/ccr subject that is not a
	// device ID, or a legacy certificate) also sailed through unchecked. Both
	// holes let a trusted-RA signer authorized under this DMS revoke a
	// certificate this DMS has no authority over, which is precisely what the
	// check exists to prevent.
	//
	// Ownership is now established from either of two independent records, then
	// enforced; when neither can establish it, the request must prove authority a
	// different way (see below).
	owner, ownerKnown, ownErr := svc.cmpCertificateOwnerDMS(ctx, lFunc, cert, input.SerialNumber)
	if ownErr != nil {
		return ownErr
	}
	switch {
	case ownerKnown && owner != dms.ID:
		lFunc.Errorf("aborting revocation of '%s': certificate is owned by DMS '%s', not '%s' (RFC 9483 §5.3.2)",
			input.SerialNumber, owner, dms.ID)
		return errs.ErrCMPDeviceOwnedByOtherDMS
	case !ownerKnown && !selfRevocation:
		// No ownership record exists for this certificate, so this DMS cannot
		// establish that it has authority over it. Self-revocation is still
		// allowed — the signer IS the target certificate and has already been
		// chain-validated against this DMS's trusted CAs above, which is authority
		// enough to revoke oneself, and it keeps legacy certificates and
		// non-device subjects (p10cr, ccr cross-certificates) revocable by their
		// holder. A THIRD PARTY, including a trusted RA, is refused: that is the
		// cross-DMS escalation path, and "we could not determine the owner" must
		// not read as "the owner is us".
		lFunc.Errorf("aborting revocation of '%s': no ownership record ties this certificate to DMS '%s', and the requester is not the certificate itself (RFC 9483 §5.3.2)",
			input.SerialNumber, dms.ID)
		return errs.ErrCMPDeviceOwnedByOtherDMS
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
		if !dms.Settings.CMP.EnrollmentSettings.RR.AllowRevival {
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

	// RFC011: RR.AllowedReasons restricts which CRLReason codes the DMS accepts.
	// Every reason an EE can request is gated here except removeFromCRL, which is
	// a hold release governed by RR.AllowRevival's check earlier in this method.
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
	opts := dms.Settings.CMP.EnrollmentSettings
	return &opts, nil
}

// LWCGetRootCACertUpdate answers a genm id-it-rootCaCert query (RFC 9483
// §4.3.2) by resolving the DMS enrollment CA's root and reporting it as the
// newWithNew certificate when it differs from the root the EE currently trusts.
//
// Lamassu reissues a root under the SAME key pair (CAServiceBackend.ReissueCA)
// — there is no genuine "old key" distinct from the "new key" to cross-sign
// with. newWithOld ::= the new certificate's public key certified by the OLD
// private key (RFC 9483 §4.3.2); since old key == new key here, that
// certification is identical to newWithNew itself, so the same certificate is
// reused for both fields rather than fabricating a distinct one. This is also
// why oldWithNew is left absent: it exists to let an EE that already trusts
// the NEW root re-validate the OLD one during rollback, which only matters
// when the two keys actually differ.
func (svc DMSManagerServiceBackend) LWCGetRootCACertUpdate(ctx context.Context, input services.GetRootCACertUpdateInput) (*services.RootCACertUpdateOutput, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{ID: input.APS})
	if err != nil {
		lFunc.Errorf("LWCGetRootCACertUpdate: could not get DMS '%s': %s", input.APS, err)
		return nil, errs.ErrDMSNotFound
	}

	known := svc.dmsKnownCAs(ctx, dms)
	if len(known) == 0 {
		lFunc.Warnf("LWCGetRootCACertUpdate: could not resolve any CA chain for DMS '%s'", input.APS)
		return nil, nil
	}

	// With no hint from the EE there is nothing to compare against, so answer
	// with the enrollment CA's root — dmsKnownCAs puts it first.
	root := known[0].Root()

	// When the EE tells us which root it currently trusts, look for the update
	// among EVERY root this DMS is authoritative for, not just the enrollment
	// CA's: caCerts hands out the managed CAs too, so the EE may well be asking
	// about one of those. Same subject = identity/key continuity (a reissued
	// root); a subject matching none of them is an unrelated CA we have no
	// linked update for.
	if input.CurrentRootCert != nil {
		match := findKnownRootBySubject(known, input.CurrentRootCert.RawSubject)
		if match == nil {
			lFunc.Debugf("LWCGetRootCACertUpdate: EE-trusted root (CN=%s) is unrelated to any CA of DMS '%s'; no update offered",
				input.CurrentRootCert.Subject.CommonName, input.APS)
			return nil, nil
		}
		if bytes.Equal(input.CurrentRootCert.Raw, match.Raw) {
			return nil, nil // already current
		}
		root = match
	}

	if root == nil {
		return nil, nil
	}
	return &services.RootCACertUpdateOutput{NewWithNew: root, NewWithOld: root}, nil
}

// findKnownRootBySubject returns the root certificate, among the chains of the
// DMS's known CAs, whose subject matches rawDN byte-for-byte. Roots are compared
// (rather than the CA certificates themselves) because a rootCaCert request
// carries the EE's trust ANCHOR, which for a DMS enrolling against an
// intermediate is the top of that intermediate's chain, not the CA cert itself.
func findKnownRootBySubject(entries []dmsCAEntry, rawDN []byte) *x509.Certificate {
	for _, e := range entries {
		root := e.Root()
		if root != nil && bytes.Equal(root.RawSubject, rawDN) {
			return root
		}
	}
	return nil
}

// LWCGetCertReqTemplate answers a genm id-it-certReqTemplate query (RFC 9483
// §4.3.3) describing what the DMS enrollment CA's issuance profile will produce.
// A template is ALWAYS returned once a profile resolves, because there is always
// at least one thing the CA controls unconditionally to advertise: the
// certificate validity (there is no "honor requested validity" mode). On top of
// that it surfaces every field the profile OVERRIDES rather than honoring from
// the request — subject, keyUsage, extendedKeyUsage — plus the public-key
// algorithms crypto-enforcement accepts. Only when no issuance profile can be
// resolved at all is nil (no template available) returned.
func (svc DMSManagerServiceBackend) LWCGetCertReqTemplate(ctx context.Context, input services.GetCertReqTemplateInput) (*services.CertReqTemplateOutput, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{ID: input.APS})
	if err != nil {
		lFunc.Errorf("LWCGetCertReqTemplate: could not get DMS '%s': %s", input.APS, err)
		return nil, errs.ErrDMSNotFound
	}

	profile, err := svc.resolveIssuanceProfile(ctx, lFunc, dms, dms.Settings.CMP.EnrollmentSettings.EnrollmentCA)
	if err != nil {
		lFunc.Warnf("LWCGetCertReqTemplate: could not resolve issuance profile for DMS '%s': %s; advertising no template", input.APS, err)
		return nil, nil
	}

	out := &services.CertReqTemplateOutput{}

	// Validity is always CA-controlled — advertise it so the EE learns the
	// certificate lifetime up-front. For a duration profile the times are
	// representative (measured from now); for a fixed-time profile NotAfter is
	// exact. This is what guarantees a template is always available.
	switch profile.Validity.Type {
	case models.Duration:
		out.NotBefore = time.Now()
		out.NotAfter = out.NotBefore.Add(time.Duration(profile.Validity.Duration))
	case models.Time:
		out.NotBefore = time.Now()
		out.NotAfter = profile.Validity.Time
	}

	// When the profile does NOT honor the requester's subject, the CA overrides
	// it with the profile's own subject — surface that mandated subject so the EE
	// fills it in instead of guessing and being silently overridden.
	if !profile.HonorSubject {
		name := chelpers.SubjectToPkixName(profile.Subject)
		if len(name.ToRDNSequence()) > 0 {
			out.Subject = x509.Certificate{Subject: name}
		}
	}

	// Advertise the key algorithms crypto-enforcement accepts so the EE picks a
	// compatible key type before enrolling. The accepted sizes travel alongside
	// them because the keySpec controls encode the constraint as a size, not as a
	// bare algorithm — an RSA modulus bit length or an EC named curve.
	if profile.CryptoEnforcement.Enabled {
		if profile.CryptoEnforcement.AllowRSAKeys {
			out.AllowedKeyAlgorithms = append(out.AllowedKeyAlgorithms, x509.RSA)
			out.AllowedRSAKeySizes = profile.CryptoEnforcement.AllowedRSAKeySizes
		}
		if profile.CryptoEnforcement.AllowECDSAKeys {
			out.AllowedKeyAlgorithms = append(out.AllowedKeyAlgorithms, x509.ECDSA)
			out.AllowedECDSAKeySizes = profile.CryptoEnforcement.AllowedECDSAKeySizes
		}
	}

	// When the profile does NOT honor the requester's keyUsage/extendedKeyUsage,
	// it assigns its own regardless of what's requested — the same
	// override-not-honor pattern as Subject above, so surface it the same way.
	if !profile.HonorKeyUsage && x509.KeyUsage(profile.KeyUsage) != 0 {
		out.KeyUsage = x509.KeyUsage(profile.KeyUsage)
	}
	if !profile.HonorExtendedKeyUsages && len(profile.ExtendedKeyUsages) > 0 {
		for _, eku := range profile.ExtendedKeyUsages {
			out.ExtKeyUsage = append(out.ExtKeyUsage, x509.ExtKeyUsage(eku))
		}
	}

	return out, nil
}

// LWCGetCRL answers a genm id-it-currentCRL / id-it-crlStatusList query
// (RFC 9483 §4.3.4) by fetching the CRL for the relevant CA from the VA service.
//
// The CA is resolved in precedence order: input.CAID when set, else
// input.IssuerRawDN matched against the DMS's known CAs (enrollment + managed),
// else the DMS enrollment CA. An IssuerRawDN naming a CA this DMS is not
// authoritative for yields no CRL (nil, nil) rather than an error — per
// RFC 9483 §4.3.4 the server provides only CRLs it actually has, and a DPN or
// issuer it does not recognise is not a client error. Notably it is also NOT an
// invitation to go fetch that CRL from an external location.
//
// The VA client is optional: a DMS manager deployed without one simply reports
// no CRL available (nil).
func (svc DMSManagerServiceBackend) LWCGetCRL(ctx context.Context, input services.GetCMPCRLInput) (*x509.RevocationList, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	if svc.vaClient == nil {
		lFunc.Warnf("LWCGetCRL: no VA client configured on DMS manager; cannot serve CRL over CMP")
		return nil, nil
	}

	caID := input.CAID
	if caID == "" {
		dms, err := svc.service.GetDMSByID(ctx, services.GetDMSByIDInput{ID: input.APS})
		if err != nil {
			lFunc.Errorf("LWCGetCRL: could not get DMS '%s': %s", input.APS, err)
			return nil, errs.ErrDMSNotFound
		}
		if len(input.IssuerRawDN) > 0 {
			match := findKnownCABySubject(svc.dmsKnownCAs(ctx, dms), input.IssuerRawDN)
			if match == nil {
				lFunc.Infof("LWCGetCRL: requested CRL source (%s) is not a CA this DMS '%s' is authoritative for; no CRL offered",
					input.IssuerName, input.APS)
				return nil, nil
			}
			caID = match.ID
		} else {
			caID = dms.Settings.CMP.EnrollmentSettings.EnrollmentCA
		}
	}

	ca, err := svc.caClient.GetCAByID(ctx, services.GetCAByIDInput{CAID: caID})
	if err != nil {
		lFunc.Errorf("LWCGetCRL: could not get CA '%s': %s", caID, err)
		return nil, err
	}
	caCert := (*x509.Certificate)(ca.Certificate.Certificate)

	crl, err := svc.vaClient.GetCRL(ctx, services.GetCRLResponseInput{
		CASubjectKeyID: ca.Certificate.SubjectKeyID,
		Issuer:         caCert,
		VerifyResponse: false,
	})
	if err != nil {
		lFunc.Errorf("LWCGetCRL: could not fetch CRL for CA '%s' (SKI %s): %s", caID, ca.Certificate.SubjectKeyID, err)
		return nil, err
	}

	// Honour the "only if newer" contract: when the caller already holds a CRL
	// at least as fresh as the one we found, report no update (nil).
	if crl != nil && !input.CurrentThisUpdate.IsZero() && !crl.ThisUpdate.After(input.CurrentThisUpdate) {
		return nil, nil
	}
	return crl, nil
}
