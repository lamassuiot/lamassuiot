package errs

import "errors"

var (
	ErrDMSNotFound        error = errors.New("DMS not found")
	ErrDMSAlreadyExists   error = errors.New("DMS already exists")
	ErrDMSIssuanceProfile error = errors.New("DMS certificate expiration exceeds that of the enrollment CA")

	ErrDMSOnlyEST              error = errors.New("DMS uses EST protocol")
	ErrDMSInvalidAuthMode      error = errors.New("DMS invalid auth mode")
	ErrDMSAuthModeNotSupported error = errors.New("DMS auth mode not supported")
	ErrDMSEnrollInvalidCert    error = errors.New("invalid certificate")
	ErrDMSInvalidProtocol      error = errors.New("DMS enrollment protocol must be EST_RFC7030 or CMP_RFC9483")

	// ErrCMPTransactionAlreadyExists is returned by CMPTransactionRepo.Insert when a live
	// transaction with the same transactionID already exists in the store.
	// The CMP controller maps this to PKIFailureInfo transactionIdInUse (21) per RFC 4210 §5.1.1.
	ErrCMPTransactionAlreadyExists error = errors.New("CMP transactionID already in use")

	// ErrCMPTransactionNotFound is returned when an admin action targets a CMP
	// transaction that does not exist (or does not belong to the given DMS).
	ErrCMPTransactionNotFound error = errors.New("CMP transaction not found")

	// ErrCMPTransactionNotPending is returned when an admin tries to approve a
	// CMP transaction that is not awaiting approval (i.e. not in PENDING state,
	// or already expired).
	ErrCMPTransactionNotPending error = errors.New("CMP transaction is not awaiting approval")

	// ErrCMPPendingUpdate is returned when a CMP operation (enrollment, key
	// update, revocation) targets a device that already has an in-flight
	// (issued-but-unconfirmed) key-update transaction. RFC 9483 §4.1.3: the
	// open transaction must complete (certConf) or time out before further
	// operations are accepted. Maps to PKIFailureInfo badRequest (2).
	ErrCMPPendingUpdate error = errors.New("a certificate update is pending confirmation for this device")

	// ErrCMPCertSuperseded is returned when the CMP protection (signer)
	// certificate was superseded by a confirmed key update (kur): per
	// RFC 9483 §4.1.3 an updated certificate can no longer authenticate
	// enrollment operations. Maps to PKIFailureInfo certRevoked (10).
	ErrCMPCertSuperseded error = errors.New("certificate has been superseded by a confirmed key update")

	// ErrCMPSignerNotActive is returned when a kur's protection certificate is
	// neither the device's active certificate nor a recognised superseded one —
	// the RFC 9483 §4.1.3 signer binding fails. Maps to PKIFailureInfo
	// badRequest (2).
	ErrCMPSignerNotActive error = errors.New("CMP signer certificate does not match device's active certificate")

	// ErrCMPAbandonedUpdate is returned by the ir/cr enrollment path when the
	// protection (signer) certificate belongs to a device whose previous
	// key-update was issued but never confirmed and has since timed out
	// (the CMP confirmation monitor revoked the unconfirmed cert). Per
	// RFC 9483 §4.1.3 (sec-awareness) such a device must recover via a new
	// key-update (kur) rather than an initialization/certification request —
	// the abandoned-update credential is no longer a valid basis for a fresh
	// enrollment. Maps to PKIFailureInfo badRequest (2).
	ErrCMPAbandonedUpdate error = errors.New("device has an abandoned key-update; a new key-update (kur) is required")

	// ErrCMPDeviceOwnedByOtherDMS is returned by LWCEnroll when the CSR's
	// device identity is already registered to a DMS other than the one the
	// request was submitted to. The requester's protection cert may be
	// perfectly trusted and sender-matched — it simply has no right to claim
	// this identity. Maps to PKIFailureInfo notAuthorized (23), RFC 9483 §3.5.
	ErrCMPDeviceOwnedByOtherDMS error = errors.New("device already registered to another DMS")
)
