package services

import (
	"context"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/pkg/v3/errs"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

var lDevice *logrus.Entry
var deviceValidate *validator.Validate

type DeviceManagerService interface {
	CreateDevice(input CreateDeviceInput) (*models.Device, error)
	GetDeviceByID(input GetDeviceByIDInput) (*models.Device, error)
	GetDevices(input GetDevicesInput) (string, error)
	GetDeviceByDMS(input GetDevicesByDMSInput) (string, error)
	UpdateDeviceStatus(input UpdateDeviceStatusInput) (*models.Device, error)
	UpdateDeviceIdentitySlot(input UpdateDeviceIdentitySlotInput) (*models.Device, error)
	UpdateDeviceMetadata(input UpdateDeviceMetadataInput) (*models.Device, error)
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
	deviceValidate = validator.New()
	return &DeviceManagerServiceImpl{
		caClient:       builder.CAClient,
		devicesStorage: builder.DevicesStorage,
	}
}

func (svc *DeviceManagerServiceImpl) SetService(service DeviceManagerService) {
	svc.service = service
}

type CreateDeviceInput struct {
	ID        string `validate:"required"`
	Alias     string
	Tags      []string
	Metadata  map[string]any
	DMSID     string `validate:"required"`
	Icon      string
	IconColor string
}

func (svc DeviceManagerServiceImpl) CreateDevice(input CreateDeviceInput) (*models.Device, error) {
	err := deviceValidate.Struct(input)
	if err != nil {
		lDevice.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}
	lDevice.Debugf("creating %s device", input.ID)
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
				Message:     "Device Created. Pending provision",
				Criticality: models.CRITICAL,
			},
		},
	}

	dev, err := svc.devicesStorage.Insert(context.Background(), device)
	if err != nil {
		lDevice.Errorf("could not insert device %s in storage engine: %s", input.ID, err)
		return nil, err
	}
	return dev, nil
}

type ProvisionDeviceSlotInput struct {
	ID     string `validate:"required"`
	SlotID string `validate:"required"`
}

type GetDevicesInput struct {
	ListInput[models.Device]
}

func (svc DeviceManagerServiceImpl) GetDevices(input GetDevicesInput) (string, error) {
	lDevice.Debugf("getting all devices")
	return svc.devicesStorage.SelectAll(context.Background(), input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, nil)
}

type GetDevicesByDMSInput struct {
	DMSID string
	ListInput[models.Device]
}

func (svc DeviceManagerServiceImpl) GetDeviceByDMS(input GetDevicesByDMSInput) (string, error) {
	lDevice.Debugf("getting all devices owned by DMS with ID=%s", input.DMSID)
	return svc.devicesStorage.SelectByDMS(context.Background(), input.DMSID, input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, nil)
}

type GetDeviceByIDInput struct {
	ID string `validate:"required"`
}

func (svc DeviceManagerServiceImpl) GetDeviceByID(input GetDeviceByIDInput) (*models.Device, error) {

	err := deviceValidate.Struct(input)
	if err != nil {
		lDevice.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}
	lDevice.Debugf("checking if device '%s' exists", input.ID)
	exists, device, err := svc.devicesStorage.SelectExists(context.Background(), input.ID)
	if err != nil {
		lDevice.Errorf("something went wrong while checking if device '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	} else if !exists {
		lDevice.Errorf("device %s can not be found in storage engine", input.ID)
		return nil, errs.ErrDeviceNotFound
	}

	return device, nil
}

type UpdateDeviceStatusInput struct {
	ID        string              `validate:"required"`
	NewStatus models.DeviceStatus `validate:"required"`
}

func (svc DeviceManagerServiceImpl) UpdateDeviceStatus(input UpdateDeviceStatusInput) (*models.Device, error) {
	err := deviceValidate.Struct(input)
	if err != nil {
		lDevice.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}
	lDevice.Debugf("checking if device '%s' exists", input.ID)
	exists, device, err := svc.devicesStorage.SelectExists(context.Background(), input.ID)
	if err != nil {
		lDevice.Errorf("something went wrong while checking if device '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	} else if !exists {
		lDevice.Errorf("device %s can not be found in storage engine", input.ID)
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
			device, err = svc.UpdateDeviceIdentitySlot(UpdateDeviceIdentitySlotInput{
				ID:   device.ID,
				Slot: *slot,
			})
			if err != nil {
				lDevice.Errorf("error while updating %s device status. could not update identity slot: %s", device.ID, err)
				return nil, err
			}
		}
	}

	device.Status = input.NewStatus
	lDevice.Debugf("updating %s device status to %s", input.ID, input.NewStatus)
	device, err = svc.devicesStorage.Update(context.Background(), device)
	if err != nil {
		lDevice.Errorf("error while updating %s device status. could not update DB: %s", device.ID, err)
		return nil, err
	}

	lDevice.Debugf("device %s status updated. new status: %s", input.ID, input.NewStatus)
	return device, nil
}

type UpdateDeviceMetadataInput struct {
	ID       string         `validate:"required"`
	Metadata map[string]any `validate:"required"`
}

func (svc DeviceManagerServiceImpl) UpdateDeviceMetadata(input UpdateDeviceMetadataInput) (*models.Device, error) {
	err := deviceValidate.Struct(input)
	if err != nil {
		lDevice.Errorf("UpdateDeviceMetadata struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lDevice.Debugf("checking if device '%s' exists", input.ID)
	exists, device, err := svc.devicesStorage.SelectExists(context.Background(), input.ID)
	if err != nil {
		lDevice.Errorf("something went wrong while checking if device '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	}

	if !exists {
		lDevice.Errorf("device %s can not be found in storage engine", input.ID)
		return nil, err
	}

	device.Metadata = input.Metadata

	lDevice.Debugf("updating %s device metadata", input.ID)
	return svc.devicesStorage.Update(context.Background(), device)

}

type UpdateDeviceIdentitySlotInput struct {
	ID   string              `validate:"required"`
	Slot models.Slot[string] `validate:"required"`
}

func (svc DeviceManagerServiceImpl) UpdateDeviceIdentitySlot(input UpdateDeviceIdentitySlotInput) (*models.Device, error) {

	err := deviceValidate.Struct(input)
	if err != nil {
		lDevice.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}
	lDevice.Debugf("checking if device '%s' exists", input.ID)
	exists, device, err := svc.devicesStorage.SelectExists(context.Background(), input.ID)
	if err != nil {
		lDevice.Errorf("something went wrong while checking if device '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	} else if !exists {
		lDevice.Errorf("device %s can not be found in storage engine", input.ID)
		return nil, errs.ErrDeviceNotFound
	}

	newSlot := input.Slot

	switch input.Slot.Status {
	case models.SlotRevoke:
		revokedCert, err := svc.caClient.UpdateCertificateStatus(context.Background(), UpdateCertificateStatusInput{
			SerialNumber:     device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion],
			NewStatus:        models.StatusRevoked,
			RevocationReason: ocsp.Unspecified,
		})
		if err != nil {
			lDevice.Errorf("could not revoke identity slot for device %s: %s", input.ID, err)
			return nil, err
		}
		newSlot.Secrets[newSlot.ActiveVersion] = revokedCert.SerialNumber
	}

	device.IdentitySlot = &newSlot

	if err != nil {
		return nil, err
	}

	lDevice.Debugf("updating %s device identity slot", input.ID)
	return svc.devicesStorage.Update(context.Background(), device)
}
