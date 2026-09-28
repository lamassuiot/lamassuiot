package cryptoenginesv2

import "errors"

// errors.go (additions)
var (
	ErrOperationNotAllowed    = errors.New("operation not allowed by algorithm or key policy")
	ErrInvalidStateTransition = errors.New("invalid key state transition")
	ErrKeyNotFound            = errors.New("key not found")
	ErrAliasNotFound          = errors.New("alias not found")
	// ErrVerificationFailed reports that a signature or MAC did not verify — a
	// valid negative result, distinct from an operational failure. Callers
	// should surface this as "not valid" rather than an internal error.
	ErrVerificationFailed = errors.New("verification failed")
)
