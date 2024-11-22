package errs

import "errors"

var (
	ErrEngineAlgNotSupported      error = errors.New("signing algorithm not supported")
	ErrEngineHashAlgInconsistency error = errors.New("inconsistency between hashed message and signature algorithm")
)
