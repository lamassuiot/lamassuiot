package models

import (
	"time"
)

// CMPTransactionState is the lifecycle state of a CMP transaction. It is the
// single vocabulary shared by the persisted cmp_transactions row and the WFX
// workflow that mirrors it (see backend/pkg/integrations/wfx): a transaction
// row and its WFX job always carry the same state name.
//
// Some states are only ever visible in WFX because the row does not rest in
// them (Received, Validated, Responded) or is never written (Rejected); the
// rest are also persisted. Actors, per transition, are documented on the WFX
// workflow definitions.
//
// Synchronous issuance inserts the row already in AwaitingCertConf (explicit
// confirmation) or LogicallyComplete (implicit confirmation). Phased issuance
// (RFC 9483 §4.4 delayed delivery) inserts it in AwaitingApproval; the admin's
// decision moves it through Approving to AwaitingCertConf/LogicallyComplete
// (cert issued) or IssueFailed.
type CMPTransactionState string

const (
	// CMPTransactionStateReceived: the request was accepted and decoded.
	// WFX-only — no row exists yet.
	CMPTransactionStateReceived CMPTransactionState = "Received"
	// CMPTransactionStateValidated: request protection and the enrollment
	// request passed validation. WFX-only.
	CMPTransactionStateValidated CMPTransactionState = "Validated"
	// CMPTransactionStateAwaitingPoPResponse: a challengeResp proof-of-possession
	// challenge (popdecc) was sent and the EE's popdecr is pending. The row
	// holds the CSR and the expected challenge answer.
	CMPTransactionStateAwaitingPoPResponse CMPTransactionState = "AwaitingPoPResponse"
	// CMPTransactionStateAwaitingApproval: phased (or ccr) request parked until
	// an administrator approves or rejects it. The row holds the CSR.
	CMPTransactionStateAwaitingApproval CMPTransactionState = "AwaitingApproval"
	// CMPTransactionStateApproving is a transient claim marker: an
	// administrator has started resolving an AwaitingApproval transaction
	// (approve or reject) via CMPTransactionRepo.ClaimPending, which
	// atomically moves the row AwaitingApproval → Approving. Only the caller
	// that wins that atomic transition proceeds to call the CA/issue the
	// certificate and persist the final state — this is what makes concurrent
	// Approve/Reject calls (double-click, client retry, a race between the
	// two, or a race with the confirmation monitor's approval-timeout sweep)
	// safe instead of racing to issue the same CSR twice. A row that never
	// leaves this state (e.g. the process crashed mid-approval) is picked up
	// by the same expired-approval sweep once its ExpiresAt passes.
	CMPTransactionStateApproving CMPTransactionState = "Approving"
	// CMPTransactionStateResponded: the certificate was issued and the
	// ip/cp/kup response emitted. WFX-only — within the request the row moves
	// straight on to AwaitingCertConf or LogicallyComplete.
	CMPTransactionStateResponded CMPTransactionState = "Responded"
	// CMPTransactionStateAwaitingCertConf: the cert has been issued and is held
	// in the row, awaiting either certConf (explicit confirmation) or expiry.
	// Both pollReq and certConf operate on rows in this state.
	CMPTransactionStateAwaitingCertConf CMPTransactionState = "AwaitingCertConf"
	// CMPTransactionStateLogicallyComplete: implicit confirmation was granted
	// (RFC 4210 §5.2.8), so the enrollment is complete at delivery and no
	// certConf is required. An EE MAY still send one; it is answered with
	// pkiConf. Retained for audit/UI visibility, never swept by DeleteExpired.
	CMPTransactionStateLogicallyComplete CMPTransactionState = "LogicallyComplete"
	// CMPTransactionStateConfirmed: the EE sent a valid certConf and the server
	// responded with pkiConf. Retained for audit/UI visibility, never swept by
	// DeleteExpired.
	CMPTransactionStateConfirmed CMPTransactionState = "Confirmed"
	// CMPTransactionStateRevoking is a transient claim marker: the
	// confirmation-timeout monitor has started revoking an expired,
	// unconfirmed transaction (CMPTransactionRepo.ClaimIssuedForRevocation,
	// which atomically moves the row AwaitingCertConf → Revoking). Only the
	// caller that wins that atomic transition proceeds to revoke the
	// certificate at the CA — this is what stops the monitor from revoking a
	// certificate that a concurrent, legitimate certConf/pollReq(implicit) just
	// confirmed: Confirm() and ClaimIssuedForRevocation both require the row to
	// still be AwaitingCertConf, so only one of a racing pair can ever win. If
	// the CA revocation call then fails the row stays in Revoking (it can no
	// longer be confirmed); the next tick re-claims it and retries, as it does
	// for a row stuck here by a crash mid-revoke.
	CMPTransactionStateRevoking CMPTransactionState = "Revoking"
	// CMPTransactionStateRevoked: the certificate enrolled in this transaction
	// has been revoked — by the confirmation monitor when certConf never
	// arrived, or later via CMP rr or another channel. The row persists for
	// audit visibility.
	CMPTransactionStateRevoked CMPTransactionState = "Revoked"
	// CMPTransactionStateRejected: the request was refused by validation,
	// policy or an administrator. Requests refused before a row exists are
	// WFX-only; an administrator's rejection of a parked request is persisted
	// (reason in ErrorMessage) so pollReq can surface it to the EE.
	CMPTransactionStateRejected CMPTransactionState = "Rejected"
	// CMPTransactionStateIssueFailed: the CA rejected the issuance. The reason
	// is stored in ErrorMessage so pollReq can surface a meaningful CMP error
	// to the EE.
	CMPTransactionStateIssueFailed CMPTransactionState = "IssueFailed"
	// CMPTransactionStateExpired: the approval or proof-of-possession window
	// elapsed with no action. The reason is stored in ErrorMessage.
	CMPTransactionStateExpired CMPTransactionState = "Expired"
)

// IsConfirmed reports whether the enrollment is complete, either by an
// explicit certConf (Confirmed) or by implicit confirmation (LogicallyComplete).
func (s CMPTransactionState) IsConfirmed() bool {
	return s == CMPTransactionStateConfirmed || s == CMPTransactionStateLogicallyComplete
}

// IsRetained reports whether a persisted row in this state is always visible
// regardless of ExpiresAt, i.e. it has left the in-flight set and is kept for
// audit rather than aged out as stale. Rejected, IssueFailed and Expired are included but
// are still deleted once their retention TTL passes (DeleteExpired).
func (s CMPTransactionState) IsRetained() bool {
	switch s {
	case CMPTransactionStateConfirmed, CMPTransactionStateLogicallyComplete,
		CMPTransactionStateRevoked, CMPTransactionStateRejected,
		CMPTransactionStateIssueFailed, CMPTransactionStateExpired:
		return true
	}
	return false
}

// CMPTransaction holds the server-side state for one CMP enrollment
// transaction, keyed by the hex-encoded transactionID from the PKIHeader.
//
// Full lifecycle:
//   - Sync issuance (default): the row is inserted directly with
//     State=AwaitingCertConf (or LogicallyComplete for implicit confirmation)
//     and CertDER populated. It persists through certConf → Confirmed, and
//     optionally through revocation → Revoked.
//   - Async issuance (RFC 9483 §4.4): the row is inserted with State=AwaitingApproval
//     and empty CertDER. A background worker calls LWCEnroll/LWCReenroll,
//     populates CertDER and transitions to AwaitingCertConf (or sets ErrorMessage and
//     transitions to IssueFailed). The EE retrieves the cert via pollReq.
//
// Confirmed, LogicallyComplete and Revoked rows are kept for audit visibility
// and are NOT subject to TTL-based deletion; Rejected, IssueFailed and Expired rows are
// visible for a retention window (ExpiresAt) and then swept by DeleteExpired.
type CMPTransaction struct {
	// TransactionID is the hex-encoded bytes from the CMP PKIHeader transactionID
	// field. Used as PRIMARY KEY; uniqueness enforced at DB level.
	TransactionID string
	// DMSID is the DMS this enrollment belongs to (path param from the request).
	DMSID string
	// CertSerialNumber is the hex-encoded serial number of the issued cert,
	// extracted from CertDER at insertion time. Stored as a denormalized column
	// to allow efficient lookup when a revocation arrives by serial.
	// Empty while the request has not been issued yet (AwaitingApproval).
	CertSerialNumber string
	// Certificate is the issued certificate that the client must confirm.
	// Stored so the server can verify the certHash in certConf.
	// Nil while the request has not been issued yet (AwaitingApproval).
	Certificate *X509Certificate
	// SentNonce is the hex-encoded senderNonce placed in the server's IP/CP/KUP response.
	// The client echoes it back as recipNonce in certConf; the server checks
	// they match (RFC 4210 §5.1.1).
	SentNonce string
	// ReceivedNonce is the hex-encoded senderNonce from the EE's initiating
	// request (ir/cr/kur). The certConf MUST carry a *fresh* senderNonce, so the
	// server rejects a certConf that reuses this value (RFC 9483 §3.1
	// badSenderNonce). Empty for legacy rows written before this was tracked.
	ReceivedNonce string
	// SupersededCertSerial is, for key-update (kur) transactions, the hex serial
	// number of the certificate being updated (the request's protection cert).
	// While this transaction is AwaitingCertConf, that certificate must
	// not start further operations (RFC 9483 §4.1.3) — see
	// HasUnconfirmedReenrollment. Empty for ir/cr transactions and for
	// unprotected (NO_AUTH) key updates.
	SupersededCertSerial string
	// RegToken is the RFC 4211 §6.1 id-regCtrl-regToken value carried by the
	// request's CertRequest controls, when present. Empty when the request
	// supplied none. Used to enforce one-time use — see HasSeenRegToken.
	RegToken string
	// PopoChallenge is the hex-encoded expected Rand.int value for an ir/cr
	// transaction AwaitingPoPResponse on a challengeResp proof-of-possession round trip
	// (RFC 4210bis §5.2.8.3, popdecc/popdecr). Empty for every other
	// transaction, including phased-workflow AwaitingApproval rows.
	PopoChallenge string
	// State is the lifecycle state of this transaction; see CMPTransactionState.
	State CMPTransactionState
	// ErrorMessage holds the CA failure reason when State == Rejected, IssueFailed or Expired.
	// Empty otherwise.
	ErrorMessage string
	// CSR is the certificate request built from the EE's CertTemplate.
	// Populated only while the row is awaiting approval or a PoP response so the async worker can re-issue
	// the call to LWCEnroll/LWCReenroll without keeping the original PKIMessage.
	// Nil once the cert is issued (the cert is stored instead).
	CSR *X509CertificateRequest
	// IsReenrollment is true when the original request was kur (re-enrollment),
	// false for ir/cr. The async worker uses this to choose LWCReenroll vs LWCEnroll.
	IsReenrollment bool
	// RequestType is the CMP body type that initiated the transaction: "ir"
	// (Initialization Request), "cr" (Certification Request), or "kur" (Key
	// Update Request). IsReenrollment is derivable from this ("kur" → true);
	// RequestType is the finer-grained record used by the UI to surface
	// whether a first-time enrollment was an ir or cr.
	RequestType string
	// CentralKeyGeneration is true when this transaction delivered an
	// RFC 9483 §4.1.6 server-generated private key alongside the certificate.
	//
	// The generated key is deliberately never persisted (it exists only long
	// enough to be wrapped into the response's EnvelopedData), so — unlike an
	// ordinary enrollment — this transaction's response can NOT be rebuilt. A
	// pollReq for such a row must therefore be refused rather than answered with
	// a bare certificate the EE holds no key for; see handlePoll. certConf and
	// the confirmation-timeout monitor work normally, since both need only the
	// certificate.
	CentralKeyGeneration bool
	// POPOMethod records which mechanism authenticated proof-of-possession of
	// the enrolled key for this transaction — i.e. WHY the server trusted that
	// the requester actually holds the private key it is certifying. It is
	// security-audit metadata: unlike RegToken/PopoChallenge (which exist to
	// enforce protocol behaviour), this field exists purely so an operator can
	// later answer "how was this device authenticated?" without re-deriving it
	// from the raw request. Possible values:
	//   - "signature"             — CRMF POPOSigningKey, a signature over the
	//     CertRequest verified with the requested public key (RFC 4211 §4.1
	//     clause 3 / models.CMPPOPOMethodSignature).
	//   - "trusted_ra"            — the request asserted raVerified and the
	//     message protection signer is a trusted PKI management entity
	//     (RFC 9483 §5.2.3.2 / models.CMPPOPOMethodTrustedRA).
	//   - "challenge_response"    — indirect POP via the popdecc/popdecr round
	//     trip (RFC 4210bis §5.2.8.3 / models.CMPPOPOMethodChallengeResponse).
	//     See ChallengeType for which challenge encoding was used.
	//   - "encrypted_certificate" — indirect POP via confidentiality-protected
	//     certificate delivery (RFC 4210bis §5.2.8.4 /
	//     models.CMPPOPOMethodEncryptedCertificate).
	//   - "csr_signature"         — p10cr: the PKCS#10 CSR's own self-signature
	//     IS the proof of possession (RFC 9483 §4.1.4). This is a fixed
	//     protocol invariant, not a configurable POPO method — see
	//     CMPP10CRSettings's doc comment — so it has no models.CMPPOPOMethod
	//     counterpart.
	//   - "kur_protection_cert"   — kur: possession is proven by the message
	//     protection made with the certificate being updated, not by a
	//     separate CRMF POPO (RFC 9483 §4.1.3). Also a fixed invariant with no
	//     models.CMPPOPOMethod counterpart.
	//   - ""                     — not applicable: rr, ccr, or an RFC 9483
	//     §4.1.6 central-key-generation (KGA) enrollment, where the server
	//     generates the key pair itself and there is no client POP to attest.
	//
	// This is a plain string rather than models.CMPPOPOMethod because that
	// type is a CONFIGURATION contract (CMPProofOfPossession.AllowedMethods —
	// what a DMS is willing to accept) and deliberately has no member for the
	// two fixed protocol invariants (csr_signature/kur_protection_cert) or for
	// "not applicable". Reusing it here would either force those into the
	// configuration enum or lose them; a plain string records exactly what
	// happened without constraining what may be configured.
	POPOMethod string
	// ChallengeType records which challengeResp encoding this transaction
	// used, and is meaningful only when POPOMethod == "challenge_response";
	// empty otherwise. See buildPOPOChallengeEntry (cmp_popo.go), which
	// chooses between the two based on the request's declared pvno
	// (RFC 9810 §7):
	//   - "legacy"         — pvno cmp2000(2): the deprecated `challenge` OCTET
	//     STRING field (RFC 4210bis §5.2.8.3 v2).
	//   - "encrypted_rand" — pvno cmp2021(3): `encryptedRand`, a CMS
	//     EnvelopedData wrapping the Rand value (RFC 9810 §5.2.8.3.3 / §7).
	ChallengeType string
	// AuthenticatorControlPresent records whether the request carried the
	// CRMF id-regCtrl-authenticator control (RFC 4211 §6.2), independent of
	// whether the DMS is configured to validate its value — see
	// corecmp.HasAuthenticatorControl. Note that this does NOT separately
	// record whether the value matched CMPEnrollmentSettings.ExpectedAuthenticator:
	// when ExpectedAuthenticator is configured and the control is present but
	// WRONG, the request is rejected before a transaction row is ever
	// persisted (see corecmp.ValidateAuthenticatorControl in
	// cmp_enrollment.go) — so "present" on a persisted row always means
	// "present and, if a value was configured to check against, valid".
	AuthenticatorControlPresent bool
	// AuthModeAtEnrollment is a denormalized copy of enrollOpts.AuthMode
	// (models.CMPAuthMode, e.g. "CLIENT_CERTIFICATE"/"NO_AUTH"/...) taken at
	// the moment this transaction was created. The DMS's auth_mode is mutable
	// configuration — an operator can change it at any time — so without this
	// copy a later look at an old transaction's authentication context would
	// silently reflect whatever the DMS is configured with TODAY rather than
	// what it required when the device actually enrolled. Stored as a plain
	// string (not models.CMPAuthMode) to match RequestType/SubjectCommonName's
	// convention in this struct.
	AuthModeAtEnrollment string
	// SubjectCommonName is the CommonName from the enrollment request's
	// CertTemplate (i.e. the device ID). Stored at insertion time so the
	// management UI can render device-keyed transaction listings without
	// reparsing the cert DER.
	SubjectCommonName string
	// WFXJobID is the UUID of the WFX job that mirrors this CMP transaction.
	// Empty when WFX integration is disabled, when the transaction did not
	// reach a state with a known device CN, or when the WFX side rejected
	// the create call. The management UI uses it to deep-link transaction
	// rows to the corresponding workflow.
	WFXJobID string
	// ConfirmedAt records when the certConf was received and validated (or, for LogicallyComplete, when implicit confirmation was granted). Zero
	// value for non-confirmed transactions.
	ConfirmedAt time.Time
	// ExpiresAt is the absolute deadline after which the transaction is
	// considered stale and eligible for deletion. Only applies to in-flight
	// states (AwaitingApproval, AwaitingPoPResponse, AwaitingCertConf) and to the retention TTL of Rejected/IssueFailed/Expired rows. Other retained states ignore this.
	ExpiresAt time.Time
	// CreatedAt records when the transaction was first persisted.
	CreatedAt time.Time
}
