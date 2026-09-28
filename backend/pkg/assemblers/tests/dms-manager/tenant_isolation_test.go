package dmsmanager

import (
	"context"
	"errors"
	"testing"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestDMSManagerTenantIsolation(t *testing.T) {
	dmsMgr, _, err := StartDMSManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create DMS Manager test server: %s", err)
	}

	tenantA := dmsTenantContext("00000000-0000-0000-0000-00000000000a")
	tenantB := dmsTenantContext("00000000-0000-0000-0000-00000000000b")
	if _, err := dmsMgr.Service.GetDMSByID(context.Background(), services.GetDMSByIDInput{ID: "missing-context"}); !errors.Is(err, core.ErrTenantContextRequired) {
		t.Fatalf("expected missing tenant context to be rejected, got %v", err)
	}
	suspendedTenant := core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-dms-isolation",
		TenantID:       "00000000-0000-0000-0000-00000000000a",
		ActorID:        "actor-dms-isolation",
		ActorType:      "test",
		CorrelationID:  "correlation-suspended",
		Source:         "test",
		TenantStatus:   core.TenantSuspended,
		Validated:      true,
	})
	if _, err := dmsMgr.Service.GetDMSByID(suspendedTenant, services.GetDMSByIDInput{ID: "missing-context"}); !errors.Is(err, core.ErrTenantContextInvalid) {
		t.Fatalf("expected suspended tenant context to be rejected, got %v", err)
	}
	dms, err := dmsMgr.Service.CreateDMS(tenantA, services.CreateDMSInput{ID: "tenant-a-dms", Name: "tenant-a"})
	if err != nil {
		t.Fatalf("could not create tenant A DMS: %s", err)
	}

	if _, err := dmsMgr.Service.GetDMSByID(tenantB, services.GetDMSByIDInput{ID: dms.ID}); !errors.Is(err, errs.ErrDMSNotFound) {
		t.Fatalf("expected tenant B DMS lookup to be hidden, got %v", err)
	}
	if _, err := dmsMgr.Service.GetDMSByID(tenantB, services.GetDMSByIDInput{ID: "unknown-dms-id"}); !errors.Is(err, errs.ErrDMSNotFound) {
		t.Fatalf("expected unknown DMS lookup to use the same not-found error, got %v", err)
	}
	if err := dmsMgr.Service.DeleteDMS(tenantB, services.DeleteDMSInput{ID: dms.ID}); !errors.Is(err, errs.ErrDMSNotFound) {
		t.Fatalf("expected tenant B DMS deletion to be rejected, got %v", err)
	}
}

func dmsTenantContext(tenantID string) context.Context {
	return core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-dms-isolation",
		TenantID:       tenantID,
		ActorID:        "actor-dms-isolation",
		ActorType:      "test",
		CorrelationID:  "correlation-" + tenantID,
		Source:         "test",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})
}
