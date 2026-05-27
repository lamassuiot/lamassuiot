package cryptoenginesv2

import "errors"

// errors.go (additions)
var (
	ErrOperationNotAllowed    = errors.New("operation not allowed by algorithm or key policy")
	ErrInvalidStateTransition = errors.New("invalid key state transition")
	ErrKeyNotFound            = errors.New("key not found")
	ErrAliasNotFound          = errors.New("alias not found")
)
