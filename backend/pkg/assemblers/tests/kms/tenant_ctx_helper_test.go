package kms

import (
	"context"

	harness "github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
)

// tenantTestCtx returns a validated TenantContext for the default test tenant,
// required by the tenant-scoped services these tests call directly.
func tenantTestCtx() context.Context {
	return harness.DefaultTenantContext()
}
