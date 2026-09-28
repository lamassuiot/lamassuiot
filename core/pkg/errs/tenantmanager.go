package errs

import "errors"

var (
	ErrTenantManagerNotFound          error = errors.New("resource not found")
	ErrTenantManagerConflict          error = errors.New("resource already exists or is in a conflicting state")
	ErrTenantManagerLastTenantAdmin   error = errors.New("tenant must keep at least one active tenant_admin")
	ErrTenantManagerSelfModification  error = errors.New("an identity cannot modify its own membership")
	ErrTenantManagerInvalidTransition error = errors.New("tenant status transition is not allowed")
	ErrTenantManagerInvalidInvitation error = errors.New("invitation is invalid, expired or already used")
	ErrTenantManagerValidation        error = errors.New("invalid request")
	ErrTenantManagerForbidden         error = errors.New("operation not authorized")
)
