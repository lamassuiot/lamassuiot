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
)
