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

	ErrDMSAuthzPolicyGrantForbidden error = errors.New("changing what the authz principal of an RA grants (its policies, mappings or Enrollment CA) requires the principal_policy grant permission of authz")
)
