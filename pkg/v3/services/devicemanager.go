package services

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/v3/errs"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage"
	"github.com/sirupsen/logrus"
)

var lDevice *logrus.Entry

type DeviceManagerService interface {
	CreateDevice(input CreateDeviceInput) (*models.Device, error)
	GetDeviceByID(input GetDeviceByIDInput) (*models.Device, error)
	GetDevices(input GetDevicesInput) (string, error)
	UpdateDeviceStatus(input UpdateDeviceStatusInput) (*models.Device, error)
	UpdateIdentitySlot(input UpdateIdentitySlotInput) (*models.Device, error)
}

type DeviceManagerServiceImpl struct {
	devicesStorage storage.DeviceManagerRepo
	caClient       CAService
	service        DeviceManagerService
}

type DeviceManagerBuilder struct {
	Logger         *logrus.Entry
	CAClient       CAService
	DevicesStorage storage.DeviceManagerRepo
}

func NewDeviceManagerService(builder DeviceManagerBuilder) DeviceManagerService {
	lDevice = builder.Logger

	return &DeviceManagerServiceImpl{
		caClient:       builder.CAClient,
		devicesStorage: builder.DevicesStorage,
	}
}

func (svc *DeviceManagerServiceImpl) SetService(service DeviceManagerService) {
	svc.service = service
}

type CreateDeviceInput struct {
	ID        string
	Alias     string
	Tags      []string
	Metadata  map[string]string
	DMSID     string
	Icon      string
	IconColor string
}

func (svc DeviceManagerServiceImpl) CreateDevice(input CreateDeviceInput) (*models.Device, error) {
	now := time.Now()

	device := &models.Device{
		ID:           input.ID,
		IdentitySlot: nil,
		Status:       models.DeviceNoIdentity,
		ExtraSlots:   map[string]*models.Slot[any]{},
		Alias:        input.Alias,
		Tags:         input.Tags,
		Metadata:     input.Metadata,
		Icon:         input.Icon,
		IconColor:    input.IconColor,
		DMSOwnerID:   input.DMSID,
		CreationDate: now,
		Logs: map[time.Time]models.LogMsg{
			now: {
				Msg:         "Device Created. Pending provision",
				Criticality: models.InfoCriticality,
			},
		},
	}

	return svc.devicesStorage.Insert(context.Background(), device)
}

type ProvisionDeviceSlotInput struct {
	ID     string
	SlotID string
}

type GetDevicesInput struct {
	ListInput[models.Device]
}

func (svc DeviceManagerServiceImpl) GetDevices(input GetDevicesInput) (string, error) {
	return svc.devicesStorage.SelectAll(context.Background(), input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, nil)
}

type GetDeviceByIDInput struct {
	ID string
}

func (svc DeviceManagerServiceImpl) GetDeviceByID(input GetDeviceByIDInput) (*models.Device, error) {
	exists, device, err := svc.devicesStorage.SelectExists(context.Background(), input.ID)
	if err != nil {
		return nil, err
	} else if !exists {
		return nil, errs.ErrDeviceNotFound
	}

	return device, nil
}

type UpdateDeviceStatusInput struct {
	ID        string
	NewStatus models.DeviceStatus
}

func (svc DeviceManagerServiceImpl) UpdateDeviceStatus(input UpdateDeviceStatusInput) (*models.Device, error) {
	exists, device, err := svc.devicesStorage.SelectExists(context.Background(), input.ID)
	if err != nil {
		return nil, err
	} else if !exists {
		return nil, errs.ErrDeviceNotFound
	}

	if input.NewStatus == models.DeviceDecommissioned {
		if device.IdentitySlot.Status == models.SlotExpired {
			lDevice.Debugf("skipping slot update. Identity slot already expired")
		} else if device.IdentitySlot.Status == models.SlotRevoke {
			lDevice.Debugf("skipping slot update. Identity slot already revoked")
		} else {
			slot := device.IdentitySlot
			slot.Status = models.SlotRevoke
			lDevice.Debugf("updating identity slot to revoke active certificate")
			device, err = svc.UpdateIdentitySlot(UpdateIdentitySlotInput{
				ID:   device.ID,
				Slot: *slot,
			})
			if err != nil {
				lDevice.Errorf("error while updating %s device status. Could not update identity slot: %s", device.ID, err)
				return nil, err
			}
		}
	}

	device.Status = input.NewStatus

	device, err = svc.devicesStorage.Update(context.Background(), device)
	if err != nil {
		lDevice.Errorf("error while updating %s device status. Could not update DB: %s", device.ID, err)
		return nil, err
	}

	return device, nil
}

type UpdateIdentitySlotInput struct {
	ID   string
	Slot models.Slot[models.Certificate]
}

func (svc DeviceManagerServiceImpl) UpdateIdentitySlot(input UpdateIdentitySlotInput) (*models.Device, error) {
	exists, device, err := svc.devicesStorage.SelectExists(context.Background(), input.ID)
	if err != nil {
		return nil, err
	} else if !exists {
		return nil, errs.ErrDeviceNotFound
	}

	newSlot := input.Slot

	switch input.Slot.Status {
	case models.SlotRevoke:
		revokedCert, err := svc.caClient.UpdateCertificateStatus(UpdateCertificateStatusInput{
			SerialNumber: device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion].SerialNumber,
			NewStatus:    models.StatusRevoked,
		})
		if err != nil {
			lDevice.Errorf("could not revoke IdentitySlot for device %s: %s", input.ID, err)
			return nil, err
		}
		newSlot.Secrets[newSlot.ActiveVersion] = *revokedCert
	}

	device.IdentitySlot = &newSlot

	if err != nil {
		return nil, err
	}

	return svc.devicesStorage.Update(context.Background(), device)
}
