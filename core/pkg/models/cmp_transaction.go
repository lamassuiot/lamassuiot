package models

import (
	"time"
)

// CMPTransactionState is the lifecycle state of a CMP transaction.
// In synchronous issuance mode (the default), transactions are created already
// in the ISSUED state. In asynchronous-issuance mode (RFC 9483 §4.4 delayed
// delivery), the controller creates the row in PENDING state and a background
// worker transitions it to ISSUED (with the cert bytes) or ISSUE_FAILED
// (with an ErrorMessage).
type CMPTransactionState string

const (
	// CMPTransactionStatePending means the enrollment request has been accepted
	// but the cert has not yet been issued. A background worker is responsible
	// for transitioning the row to ISSUED or ISSUE_FAILED.
	CMPTransactionStatePending CMPTransactionState = "PENDING"
	// CMPTransactionStateApproving is a transient claim marker: an
	// administrator has started resolving a PENDING phased-workflow
	// transaction (approve or reject) via CMPTransactionRepo.ClaimPending,
	// which atomically moves the row PENDING → APPROVING. Only the caller
	// that wins that atomic transition proceeds to call the CA/issue the
	// certificate and persist the final ISSUED/ISSUE_FAILED state — this is
	// what makes concurrent Approve/Reject calls (double-click, client
	// retry, a race between the two, or a race with the confirmation
	// monitor's approval-timeout sweep) safe instead of racing to issue the
	// same CSR twice. A row that never leaves this state (e.g. the process
	// crashed mid-approval) is picked up by the same expired-PENDING sweep
	// once its ExpiresAt passes, exactly like an unresolved PENDING row.
	CMPTransactionStateApproving CMPTransactionState = "APPROVING"
	// CMPTransactionStateIssued means the cert has been issued and is held in
	// the row's CertDER, awaiting either certConf (explicit confirmation)
	// or expiry. Both pollReq and certConf operate on rows in this state.
	CMPTransactionStateIssued CMPTransactionState = "ISSUED"
	// CMPTransactionStateIssueFailed means the async worker tried to issue the
	// cert but the CA rejected the request. The reason is stored in
	// ErrorMessage so pollReq can surface a meaningful CMP error to the EE.
	CMPTransactionStateIssueFailed CMPTransactionState = "ISSUE_FAILED"
	// CMPTransactionStateConfirmed means the EE sent a valid certConf and the
	// server responded with pkiConf. The enrollment is complete. Rows in this
	// state are retained for audit/UI visibility and are NOT swept by
	// DeleteExpired.
	CMPTransactionStateConfirmed CMPTransactionState = "CONFIRMED"
	// CMPTransactionStateRevoked means the certificate that was enrolled in
	// this transaction has been subsequently revoked (via CMP rr or other
	// channel). The row persists for audit visibility.
	CMPTransactionStateRevoked CMPTransactionState = "REVOKED"
	// CMPTransactionStateRevoking is a transient claim marker: the
	// confirmation-timeout monitor has started revoking an expired,
	// unconfirmed ISSUED transaction (CMPTransactionRepo.
	// ClaimIssuedForRevocation, which atomically moves the row
	// ISSUED → REVOKING). Only the caller that wins that atomic transition
	// proceeds to revoke the certificate at the CA — this is what stops the
	// monitor from revoking a certificate that a concurrent, legitimate
	// certConf/pollReq(implicit) just confirmed: Confirm() and
	// ClaimIssuedForRevocation both require the row to still be ISSUED, so
	// only one of a racing pair can ever win. If the CA revocation call then
	// fails, the row is rolled back to ISSUED (still expired) so the next
	// tick retries; a row stuck here (e.g. the process crashed mid-revoke) is
	// picked up by the same expired-ISSUED sweep as an unresolved ISSUED row.
	CMPTransactionStateRevoking CMPTransactionState = "REVOKING"
)

// CMPTransaction holds the server-side state for one CMP enrollment
// transaction, keyed by the hex-encoded transactionID from the PKIHeader.
//
// Full lifecycle:
//   - Sync issuance (default): the row is inserted directly with State=ISSUED
//     and CertDER populated. It persists through certConf → CONFIRMED, and
//     optionally through revocation → REVOKED.
//   - Async issuance (RFC 9483 §4.4): the row is inserted with State=PENDING
//     and empty CertDER. A background worker calls LWCEnroll/LWCReenroll,
//     populates CertDER and transitions to ISSUED (or sets ErrorMessage and
//     transitions to ISSUE_FAILED). The EE retrieves the cert via pollReq.
//
// Terminal states (CONFIRMED, REVOKED) are retained for audit visibility and
// are NOT subject to TTL-based deletion.
type CMPTransaction struct {
	// TransactionID is the hex-encoded bytes from the CMP PKIHeader transactionID
	// field. Used as PRIMARY KEY; uniqueness enforced at DB level.
	TransactionID string
	// DMSID is the DMS this enrollment belongs to (path param from the request).
	DMSID string
	// CertSerialNumber is the hex-encoded serial number of the issued cert,
	// extracted from CertDER at insertion time. Stored as a denormalized column
	// to allow efficient lookup when a revocation arrives by serial.
	// Empty when State == PENDING.
	CertSerialNumber string
	// Certificate is the issued certificate that the client must confirm.
	// Stored so the server can verify the certHash in certConf.
	// Nil when State == PENDING.
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
	// While this transaction is ISSUED-but-unconfirmed, that certificate must
	// not start further operations (RFC 9483 §4.1.3) — see
	// HasUnconfirmedReenrollment. Empty for ir/cr transactions and for
	// unprotected (NO_AUTH) key updates.
	SupersededCertSerial string
	// RegToken is the RFC 4211 §6.1 id-regCtrl-regToken value carried by the
	// request's CertRequest controls, when present. Empty when the request
	// supplied none. Used to enforce one-time use — see HasSeenRegToken.
	RegToken string
	// PopoChallenge is the hex-encoded expected Rand.int value for an ir/cr
	// transaction PENDING a challengeResp proof-of-possession round trip
	// (RFC 4210bis §5.2.8.3, popdecc/popdecr). Empty for every other
	// transaction, including phased-workflow PENDING rows.
	PopoChallenge string
	// State is the lifecycle state of this transaction; see CMPTransactionState.
	State CMPTransactionState
	// ErrorMessage holds the CA failure reason when State == ISSUE_FAILED.
	// Empty otherwise.
	ErrorMessage string
	// CSR is the certificate request built from the EE's CertTemplate.
	// Populated only when State == PENDING so the async worker can re-issue
	// the call to LWCEnroll/LWCReenroll without keeping the original PKIMessage.
	// Nil when State == ISSUED (the cert is stored instead).
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
	// ConfirmedAt records when the certConf was received and validated. Zero
	// value for non-confirmed transactions.
	ConfirmedAt time.Time
	// ExpiresAt is the absolute deadline after which the transaction is
	// considered stale and eligible for deletion. Only applies to in-flight
	// states (PENDING, ISSUED, ISSUE_FAILED). Terminal states ignore this.
	ExpiresAt time.Time
	// CreatedAt records when the transaction was first persisted.
	CreatedAt time.Time
}
