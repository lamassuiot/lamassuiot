package errs

import "errors"

var (
	ErrDMSNotFound        error = errors.New("DMS not found")
	ErrDMSAlreadyExists   error = errors.New("DMS already exists")
	ErrDMSIssuanceProfile error = errors.New("DMS certificate expiration exceeds that of the enrollment CA")
	// ErrDMSIssuanceProfileOverridesCN is returned when a DMS would issue certificates with a profile that replaces
	// the CSR CommonName: the CommonName is the device ID, so the certificate would name another device.
	ErrDMSIssuanceProfileOverridesCN error = errors.New("DMS issuance profile overrides the certificate CommonName, which must be the device ID")

	ErrDMSOnlyEST              error = errors.New("DMS uses EST protocol")
	ErrDMSInvalidAuthMode      error = errors.New("DMS invalid auth mode")
	ErrDMSAuthModeNotSupported error = errors.New("DMS auth mode not supported")
	ErrDMSEnrollInvalidCert    error = errors.New("invalid certificate")
)
