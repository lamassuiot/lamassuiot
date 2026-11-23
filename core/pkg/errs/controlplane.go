package errs

import "errors"

var (
	ErrInvalidTenant              error = errors.New("invalid tenant")
	ErrTenantNotFound             error = errors.New("tenant not found")
	ErrTenantContextRequired      error = errors.New("tenant context required")
	ErrTenantContextInvalid       error = errors.New("invalid tenant context")
	ErrTenantResourceAccessDenied error = errors.New("tenant resource access denied")
)
