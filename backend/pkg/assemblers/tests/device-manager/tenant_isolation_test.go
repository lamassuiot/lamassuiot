package devicemanager

import (
	"context"
	"errors"
	"testing"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestDeviceManagerTenantIsolation(t *testing.T) {
	dmgr, _, err := StartDeviceManagerServiceTestServer(t, false, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}

	tenantA := deviceManagerTenantContext("00000000-0000-0000-0000-00000000000a")
	tenantB := deviceManagerTenantContext("00000000-0000-0000-0000-00000000000b")
	if _, err := dmgr.Service.GetDeviceByID(context.Background(), services.GetDeviceByIDInput{ID: "missing-context"}); !errors.Is(err, core.ErrTenantContextRequired) {
		t.Fatalf("expected missing tenant context to be rejected, got %v", err)
	}
	suspendedTenant := core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-device-isolation",
		TenantID:       "00000000-0000-0000-0000-00000000000a",
		ActorID:        "actor-device-isolation",
		ActorType:      "test",
		CorrelationID:  "correlation-suspended",
		Source:         "test",
		TenantStatus:   core.TenantSuspended,
		Validated:      true,
	})
	if _, err := dmgr.Service.GetDeviceByID(suspendedTenant, services.GetDeviceByIDInput{ID: "missing-context"}); !errors.Is(err, core.ErrTenantContextInvalid) {
		t.Fatalf("expected suspended tenant context to be rejected, got %v", err)
	}
	device, err := dmgr.Service.CreateDevice(tenantA, services.CreateDeviceInput{
		ID:        "tenant-a-device",
		DMSID:     "tenant-a-dms",
		Icon:      "device",
		IconColor: "#000000",
	})
	if err != nil {
		t.Fatalf("could not create tenant A device: %s", err)
	}

	if _, err := dmgr.Service.GetDeviceByID(tenantB, services.GetDeviceByIDInput{ID: device.ID}); !errors.Is(err, errs.ErrDeviceNotFound) {
		t.Fatalf("expected tenant B device lookup to be hidden, got %v", err)
	}
	if _, err := dmgr.Service.GetDeviceByID(tenantB, services.GetDeviceByIDInput{ID: "unknown-device-id"}); !errors.Is(err, errs.ErrDeviceNotFound) {
		t.Fatalf("expected unknown device lookup to use the same not-found error, got %v", err)
	}
	if err := dmgr.Service.DeleteDevice(tenantB, services.DeleteDeviceInput{ID: device.ID}); !errors.Is(err, errs.ErrDeviceNotFound) {
		t.Fatalf("expected tenant B device deletion to be rejected, got %v", err)
	}
}

func deviceManagerTenantContext(tenantID string) context.Context {
	return core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-device-isolation",
		TenantID:       tenantID,
		ActorID:        "actor-device-isolation",
		ActorType:      "test",
		CorrelationID:  "correlation-" + tenantID,
		Source:         "test",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})
}
