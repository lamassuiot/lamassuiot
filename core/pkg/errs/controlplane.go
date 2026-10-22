package errs

import "errors"

var (
	ErrInvalidTenant              error = errors.New("invalid tenant")
	ErrInvalidMembership          error = errors.New("invalid membership")
	ErrTenantContextRequired      error = errors.New("tenant context required")
	ErrTenantContextInvalid       error = errors.New("invalid tenant context")
	ErrTenantResourceAccessDenied error = errors.New("tenant resource access denied")
)
