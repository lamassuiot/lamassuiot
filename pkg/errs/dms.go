package errs

import "errors"

var (
	ErrDMSNotFound      error = errors.New("DMS not found")
	ErrDMSAlreadyExists error = errors.New("DMS already exists")

	ErrDMSOnlyEST              error = errors.New("DMS uses EST protocol")
	ErrDMSInvalidAuthMode      error = errors.New("DMS invalid auth mode")
	ErrDMSAuthModeNotSupported error = errors.New("DMS auth mode not supported")
	ErrDMSEnrollInvalidCert    error = errors.New("invalid certificate")
)
