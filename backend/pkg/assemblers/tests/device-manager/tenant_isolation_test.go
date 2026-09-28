package devicemanager

import (
	"context"
	"errors"
	"testing"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
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

// TestDeviceManagerTenantIsolationAcrossOperations amplía la matriz A/B de
// 003 T10 a lecturas, listados, estadísticas, modificaciones y grupos, y
// comprueba que ninguna operación del servicio acepta llamadas sin tenant.
func TestDeviceManagerTenantIsolationAcrossOperations(t *testing.T) {
	dmgr, _, err := StartDeviceManagerServiceTestServer(t, false, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}

	tenantA := deviceManagerTenantContext("00000000-0000-0000-0000-00000000000c")
	tenantB := deviceManagerTenantContext("00000000-0000-0000-0000-00000000000d")
	svc := dmgr.Service

	deviceA, err := svc.CreateDevice(tenantA, services.CreateDeviceInput{ID: "tenant-c-device", DMSID: "tenant-c-dms", Icon: "device", IconColor: "#000000", Tags: []string{"tenant-c"}})
	if err != nil {
		t.Fatalf("could not create tenant A device: %s", err)
	}
	if deviceA.TenantID != "00000000-0000-0000-0000-00000000000c" {
		t.Fatalf("expected tenant A device to carry tenant A, got %q", deviceA.TenantID)
	}
	criteria := []models.DeviceGroupFilterOption{{Field: "tags", FilterOperation: int(resources.StringArrayContains), Value: "tenant-c"}}
	groupA, err := svc.CreateDeviceGroup(tenantA, services.CreateDeviceGroupInput{ID: "00000000-0000-0000-0000-0000000000c1", Name: "tenant-c-group", Criteria: criteria})
	if err != nil {
		t.Fatalf("could not create tenant A group: %s", err)
	}

	// Sin contexto de tenant ninguna operación llega al almacenamiento.
	if _, err := svc.GetDevices(context.Background(), services.GetDevicesInput{ListInput: resources.ListInput[models.Device]{ApplyFunc: func(models.Device) {}}}); !errors.Is(err, core.ErrTenantContextRequired) {
		t.Fatalf("expected listing without tenant context to be rejected, got %v", err)
	}
	if _, err := svc.GetDevicesStats(context.Background(), services.GetDevicesStatsInput{}); !errors.Is(err, core.ErrTenantContextRequired) {
		t.Fatalf("expected stats without tenant context to be rejected, got %v", err)
	}
	if _, err := svc.GetDeviceGroupByID(context.Background(), services.GetDeviceGroupByIDInput{ID: groupA.ID}); !errors.Is(err, core.ErrTenantContextRequired) {
		t.Fatalf("expected group lookup without tenant context to be rejected, got %v", err)
	}
	if _, err := svc.CreateDevice(context.Background(), services.CreateDeviceInput{ID: "no-tenant-device", DMSID: "dms", Icon: "device", IconColor: "#000000"}); !errors.Is(err, core.ErrTenantContextRequired) {
		t.Fatalf("expected creation without tenant context to be rejected, got %v", err)
	}

	// Tenant B no ve ni modifica datos de A.
	var listedByB []string
	if _, err := svc.GetDevices(tenantB, services.GetDevicesInput{ListInput: resources.ListInput[models.Device]{ExhaustiveRun: true, QueryParameters: &resources.QueryParameters{}, ApplyFunc: func(d models.Device) { listedByB = append(listedByB, d.ID) }}}); err != nil {
		t.Fatalf("unexpected tenant B listing error: %s", err)
	}
	for _, id := range listedByB {
		if id == deviceA.ID {
			t.Fatal("tenant B listing exposed tenant A device")
		}
	}
	statsB, err := svc.GetDevicesStats(tenantB, services.GetDevicesStatsInput{})
	if err != nil {
		t.Fatalf("unexpected tenant B stats error: %s", err)
	}
	if statsB.TotalDevices != 0 {
		t.Fatalf("expected tenant B stats to exclude tenant A devices, got %d", statsB.TotalDevices)
	}
	if _, err := svc.UpdateDeviceMetadata(tenantB, services.UpdateDeviceMetadataInput{ID: deviceA.ID, Patches: []models.PatchOperation{}}); !errors.Is(err, errs.ErrDeviceNotFound) {
		t.Fatalf("expected tenant B metadata update to be hidden, got %v", err)
	}
	if _, err := svc.UpdateDeviceStatus(tenantB, services.UpdateDeviceStatusInput{ID: deviceA.ID, NewStatus: models.DeviceDecommissioned}); !errors.Is(err, errs.ErrDeviceNotFound) {
		t.Fatalf("expected tenant B status update to be hidden, got %v", err)
	}
	if _, err := svc.GetDeviceGroupByID(tenantB, services.GetDeviceGroupByIDInput{ID: groupA.ID}); !errors.Is(err, errs.ErrDeviceGroupNotFound) {
		t.Fatalf("expected tenant B group lookup to be hidden, got %v", err)
	}
	if _, err := svc.GetDevicesByGroup(tenantB, services.GetDevicesByGroupInput{GroupID: groupA.ID, ListInput: resources.ListInput[models.Device]{QueryParameters: &resources.QueryParameters{}, ApplyFunc: func(models.Device) {}}}); !errors.Is(err, errs.ErrDeviceGroupNotFound) {
		t.Fatalf("expected tenant B group device listing to be hidden, got %v", err)
	}
	if err := svc.DeleteDeviceGroup(tenantB, services.DeleteDeviceGroupInput{ID: groupA.ID}); !errors.Is(err, errs.ErrDeviceGroupNotFound) {
		t.Fatalf("expected tenant B group deletion to be rejected, got %v", err)
	}

	// Los datos de A siguen intactos para A.
	stillA, err := svc.GetDeviceByID(tenantA, services.GetDeviceByIDInput{ID: deviceA.ID})
	if err != nil {
		t.Fatalf("tenant A lost access to its device: %s", err)
	}
	if stillA.Status != deviceA.Status {
		t.Fatalf("tenant A device status changed from %s to %s", deviceA.Status, stillA.Status)
	}
	if _, err := svc.GetDeviceGroupByID(tenantA, services.GetDeviceGroupByIDInput{ID: groupA.ID}); err != nil {
		t.Fatalf("tenant A lost access to its group: %s", err)
	}
}
