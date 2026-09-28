package services

import (
	"context"
	"errors"
	"testing"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

// deviceManagerUnreachableRepo falla ante cualquier acceso: el repositorio
// embebido es nil, así que llamar a un método provoca un pánico que el test
// convierte en fallo. Sirve para demostrar que el servicio rechaza la
// operación antes de tocar el almacenamiento.
type deviceManagerUnreachableRepo struct {
	storage.DeviceManagerRepo
}

func deviceManagerTenantOperations() map[string]func(context.Context, services.DeviceManagerService) error {
	parentID := "parent-group"
	listDevices := resources.ListInput[models.Device]{QueryParameters: &resources.QueryParameters{}, ApplyFunc: func(models.Device) {}}
	listGroups := resources.ListInput[models.DeviceGroup]{QueryParameters: &resources.QueryParameters{}, ApplyFunc: func(models.DeviceGroup) {}}
	criteria := []models.DeviceGroupFilterOption{{Field: "tags", FilterOperation: int(resources.StringArrayContains), Value: "a"}}

	return map[string]func(context.Context, services.DeviceManagerService) error{
		"GetDevicesStats": func(ctx context.Context, svc services.DeviceManagerService) error {
			_, err := svc.GetDevicesStats(ctx, services.GetDevicesStatsInput{})
			return err
		},
		"CreateDevice": func(ctx context.Context, svc services.DeviceManagerService) error {
			_, err := svc.CreateDevice(ctx, services.CreateDeviceInput{ID: "device", DMSID: "dms", Icon: "icon", IconColor: "#000000"})
			return err
		},
		"GetDeviceByID": func(ctx context.Context, svc services.DeviceManagerService) error {
			_, err := svc.GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: "device"})
			return err
		},
		"GetDevices": func(ctx context.Context, svc services.DeviceManagerService) error {
			_, err := svc.GetDevices(ctx, services.GetDevicesInput{ListInput: listDevices})
			return err
		},
		"GetDeviceByDMS": func(ctx context.Context, svc services.DeviceManagerService) error {
			_, err := svc.GetDeviceByDMS(ctx, services.GetDevicesByDMSInput{DMSID: "dms", ListInput: listDevices})
			return err
		},
		"UpdateDeviceStatus": func(ctx context.Context, svc services.DeviceManagerService) error {
			_, err := svc.UpdateDeviceStatus(ctx, services.UpdateDeviceStatusInput{ID: "device", NewStatus: models.DeviceActive})
			return err
		},
		"UpdateDeviceMetadata": func(ctx context.Context, svc services.DeviceManagerService) error {
			_, err := svc.UpdateDeviceMetadata(ctx, services.UpdateDeviceMetadataInput{ID: "device", Patches: []models.PatchOperation{}})
			return err
		},
		"UpdateDeviceIdentitySlot": func(ctx context.Context, svc services.DeviceManagerService) error {
			_, err := svc.UpdateDeviceIdentitySlot(ctx, services.UpdateDeviceIdentitySlotInput{ID: "device", Slot: models.Slot[string]{Status: models.SlotActive}})
			return err
		},
		"DeleteDevice": func(ctx context.Context, svc services.DeviceManagerService) error {
			return svc.DeleteDevice(ctx, services.DeleteDeviceInput{ID: "device"})
		},
		"CreateDeviceGroup": func(ctx context.Context, svc services.DeviceManagerService) error {
			_, err := svc.CreateDeviceGroup(ctx, services.CreateDeviceGroupInput{ID: "group", Name: "group", ParentID: &parentID, Criteria: criteria})
			return err
		},
		"UpdateDeviceGroup": func(ctx context.Context, svc services.DeviceManagerService) error {
			_, err := svc.UpdateDeviceGroup(ctx, services.UpdateDeviceGroupInput{ID: "group", Name: "group", Criteria: criteria})
			return err
		},
		"DeleteDeviceGroup": func(ctx context.Context, svc services.DeviceManagerService) error {
			return svc.DeleteDeviceGroup(ctx, services.DeleteDeviceGroupInput{ID: "group"})
		},
		"GetDeviceGroupByID": func(ctx context.Context, svc services.DeviceManagerService) error {
			_, err := svc.GetDeviceGroupByID(ctx, services.GetDeviceGroupByIDInput{ID: "group"})
			return err
		},
		"GetDeviceGroups": func(ctx context.Context, svc services.DeviceManagerService) error {
			_, err := svc.GetDeviceGroups(ctx, services.GetDeviceGroupsInput{ListInput: listGroups})
			return err
		},
		"GetDevicesByGroup": func(ctx context.Context, svc services.DeviceManagerService) error {
			_, err := svc.GetDevicesByGroup(ctx, services.GetDevicesByGroupInput{GroupID: "group", ListInput: listDevices})
			return err
		},
		"GetDeviceGroupStats": func(ctx context.Context, svc services.DeviceManagerService) error {
			_, err := svc.GetDeviceGroupStats(ctx, services.GetDeviceGroupStatsInput{GroupID: "group"})
			return err
		},
	}
}

func callDeviceManagerOperation(ctx context.Context, svc services.DeviceManagerService, operation func(context.Context, services.DeviceManagerService) error) (err error, reachedStorage bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			reachedStorage = true
		}
	}()
	return operation(ctx, svc), false
}

func TestDeviceManagerOperationsRequireTenantContext(t *testing.T) {
	svc := NewDeviceManagerService(DeviceManagerBuilder{
		Logger:         logrus.NewEntry(logrus.New()),
		DevicesStorage: deviceManagerUnreachableRepo{},
	})

	suspendedTenant := core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "organization",
		TenantID:       "tenant-a",
		ActorID:        "actor",
		ActorType:      "user",
		CorrelationID:  "correlation",
		Source:         "test",
		TenantStatus:   core.TenantSuspended,
		Validated:      true,
	})

	contexts := []struct {
		name    string
		ctx     context.Context
		wantErr error
	}{
		{name: "sin contexto", ctx: context.Background(), wantErr: core.ErrTenantContextRequired},
		{name: "tenant suspendido", ctx: suspendedTenant, wantErr: core.ErrTenantContextInvalid},
	}

	operations := deviceManagerTenantOperations()
	if len(operations) != 16 {
		t.Fatalf("la tabla debe cubrir los 16 métodos públicos de DeviceManagerService, cubre %d", len(operations))
	}

	for _, tc := range contexts {
		for name, operation := range operations {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				err, reachedStorage := callDeviceManagerOperation(tc.ctx, svc, operation)
				if reachedStorage {
					t.Fatalf("%s llegó al repositorio sin un contexto de tenant válido", name)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("se esperaba %v, se obtuvo %v", tc.wantErr, err)
				}
			})
		}
	}
}

// deviceManagerTenantRecordingRepo registra el tenant del contexto con el que
// el servicio llama al repositorio.
type deviceManagerTenantRecordingRepo struct {
	storage.DeviceManagerRepo
	seenTenants *[]string
}

func (repo deviceManagerTenantRecordingRepo) SelectExists(ctx context.Context, _ string) (bool, *models.Device, error) {
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return false, nil, err
	}
	*repo.seenTenants = append(*repo.seenTenants, tenantContext.TenantID)
	return false, nil, nil
}

func TestDeviceManagerPropagatesCallerTenantToRepository(t *testing.T) {
	var seenTenants []string
	svc := NewDeviceManagerService(DeviceManagerBuilder{
		Logger:         logrus.NewEntry(logrus.New()),
		DevicesStorage: deviceManagerTenantRecordingRepo{seenTenants: &seenTenants},
	})

	if _, err := svc.GetDeviceByID(testKMSValidTenantContext("tenant-a"), services.GetDeviceByIDInput{ID: "device-b"}); err == nil {
		t.Fatal("se esperaba dispositivo no encontrado")
	}
	if len(seenTenants) != 1 || seenTenants[0] != "tenant-a" {
		t.Fatalf("el repositorio debe consultarse solo con el tenant del llamante, vio %v", seenTenants)
	}
}

// deviceManagerInsertRecordingRepo devuelve lo que el servicio intenta
// insertar para comprobar el TenantID que asigna.
type deviceManagerInsertRecordingRepo struct {
	storage.DeviceManagerRepo
	insertedDevice *models.Device
	groups         *deviceGroupsInsertRecordingRepo
}

func (repo *deviceManagerInsertRecordingRepo) Insert(_ context.Context, device *models.Device) (*models.Device, error) {
	repo.insertedDevice = device
	return device, nil
}

func (repo *deviceManagerInsertRecordingRepo) DeviceGroups() storage.DeviceGroupsRepo {
	return repo.groups
}

type deviceGroupsInsertRecordingRepo struct {
	storage.DeviceGroupsRepo
	insertedGroup *models.DeviceGroup
}

func (repo *deviceGroupsInsertRecordingRepo) Insert(_ context.Context, group *models.DeviceGroup) (*models.DeviceGroup, error) {
	repo.insertedGroup = group
	return group, nil
}

func (repo *deviceGroupsInsertRecordingRepo) SelectAncestors(context.Context, string) ([]*models.DeviceGroup, error) {
	return []*models.DeviceGroup{}, nil
}

func TestDeviceManagerCreateAssignsTenantFromContext(t *testing.T) {
	repo := &deviceManagerInsertRecordingRepo{groups: &deviceGroupsInsertRecordingRepo{}}
	svc := NewDeviceManagerService(DeviceManagerBuilder{
		Logger:         logrus.NewEntry(logrus.New()),
		DevicesStorage: repo,
	})
	tenantA := testKMSValidTenantContext("tenant-a")

	if _, err := svc.CreateDevice(tenantA, services.CreateDeviceInput{ID: "device", DMSID: "dms", Icon: "icon", IconColor: "#000000"}); err != nil {
		t.Fatalf("error inesperado creando dispositivo: %v", err)
	}
	if repo.insertedDevice == nil || repo.insertedDevice.TenantID != "tenant-a" {
		t.Fatalf("el dispositivo debe crearse con el tenant del contexto, se insertó %+v", repo.insertedDevice)
	}

	criteria := []models.DeviceGroupFilterOption{{Field: "tags", FilterOperation: int(resources.StringArrayContains), Value: "a"}}
	if _, err := svc.CreateDeviceGroup(tenantA, services.CreateDeviceGroupInput{ID: "group", Name: "group", Criteria: criteria}); err != nil {
		t.Fatalf("error inesperado creando grupo: %v", err)
	}
	if repo.groups.insertedGroup == nil || repo.groups.insertedGroup.TenantID != "tenant-a" {
		t.Fatalf("el grupo debe crearse con el tenant del contexto, se insertó %+v", repo.groups.insertedGroup)
	}
}
