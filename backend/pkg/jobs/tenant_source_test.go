package jobs

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	svcmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/stretchr/testify/mock"
)

// Tenant source policy shared by the background jobs: work is only done for
// tenants returned by the control plane lister, each under its own validated
// TenantContext. Without a lister, or when listing fails, the run does
// nothing; invalid tenant records are skipped.

var invalidTenantRecords = []models.Tenant{
	{ID: "", OrganizationID: "org-x", Status: models.TenantActive},
	{ID: "tenant-no-org", OrganizationID: "", Status: models.TenantActive},
	{ID: "tenant-suspended", OrganizationID: "org-s", Status: models.TenantSuspended},
}

func TestTenantScopedJobsDoNothingWithoutTenantSource(t *testing.T) {
	for name, lister := range map[string]*activeTenantListerStub{
		"no lister":      nil,
		"listing fails":  {err: errors.New("control plane unavailable")},
		"no valid rows":  {tenants: invalidTenantRecords},
		"no tenants yet": {tenants: []models.Tenant{}},
	} {
		t.Run(name, func(t *testing.T) {
			caService := new(svcmock.MockCAService)
			crypto := NewCryptoMonitor(caService, helpers.SetupLogger("error", "CA", "Crypto Monitor"))
			vaService := new(svcmock.MockVAService)
			crl := NewVACrlMonitorJob(helpers.SetupLogger("error", "VA", "CRL Monitor"), vaService, time.Minute)
			if lister != nil {
				crypto.SetTenantLister(*lister)
				crl.SetTenantLister(*lister)
			}

			crypto.Run()
			crl.Run()

			caService.AssertNotCalled(t, "GetCAs", mock.Anything, mock.Anything)
			caService.AssertNotCalled(t, "GetCertificatesByStatus", mock.Anything, mock.Anything)
			vaService.AssertNotCalled(t, "GetVARoles", mock.Anything, mock.Anything)
		})
	}
}

func TestTenantScopedJobsSkipInvalidRecordsAndIsolateTenantFailures(t *testing.T) {
	tenants := append([]models.Tenant{
		{ID: "tenant-a", OrganizationID: "org-a", Status: models.TenantActive},
		{ID: "tenant-b", OrganizationID: "org-b", Status: models.TenantActive},
	}, invalidTenantRecords...)

	vaService := new(svcmock.MockVAService)
	crl := NewVACrlMonitorJob(helpers.SetupLogger("error", "VA", "CRL Monitor"), vaService, time.Minute)
	crl.SetTenantLister(activeTenantListerStub{tenants: tenants})

	var mu sync.Mutex
	seen := map[string]bool{}
	record := func(args mock.Arguments) {
		tenantContext, err := core.RequireTenantContext(args.Get(0).(context.Context))
		if err != nil {
			t.Errorf("GetVARoles received invalid tenant context: %s", err)
			return
		}
		mu.Lock()
		seen[tenantContext.TenantID] = true
		mu.Unlock()
	}
	forTenant := func(tenantID string) any {
		return mock.MatchedBy(func(ctx context.Context) bool {
			tenantContext, err := core.RequireTenantContext(ctx)
			return err == nil && tenantContext.TenantID == tenantID
		})
	}
	noRoles := []*models.VARole{}
	vaService.On("GetVARoles", forTenant("tenant-a"), mock.Anything).Run(record).Return(&noRoles, errors.New("tenant A storage failure"))
	vaService.On("GetVARoles", forTenant("tenant-b"), mock.Anything).Run(record).Return(&noRoles, nil)

	crl.Run()

	if len(seen) != 2 || !seen["tenant-a"] || !seen["tenant-b"] {
		t.Fatalf("expected only the two valid tenants to be processed, even if tenant A fails; got %v", seen)
	}
}
