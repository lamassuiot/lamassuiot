package errs

import "errors"

var (
	ErrCRLSettingsNotFound  error = errors.New("CRL settings not found")
	ErrCRLSettingsNotActive error = errors.New("CRL settings are not active")
	ErrCRLNotFound          error = errors.New("CRL not found")
	ErrCRLSettingsConflict  error = errors.New("CRL settings were modified concurrently")
)
