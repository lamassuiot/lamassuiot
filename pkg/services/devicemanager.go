package services

import (
	"context"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/v2/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

var lDevice *logrus.Entry
var deviceValidate *validator.Validate

type DeviceMiddleware func(DeviceManagerService) DeviceManagerService

type DeviceManagerService interface {
	GetDevicesStats(input GetDevicesStatsInput) (*models.DevicesStats, error)
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

type GetDevicesStatsInput struct {
}

func (svc *DeviceManagerServiceImpl) GetDevicesStats(input GetDevicesStatsInput) (*models.DevicesStats, error) {
	stats := models.DevicesStats{
		TotalDevices:  -1,
		DevicesStatus: map[models.DeviceStatus]int{},
	}

	allStatus := []models.DeviceStatus{
		models.DeviceNoIdentity,
		models.DeviceActive,
		models.DeviceRenewalWindow,
		models.DeviceAboutToExpire,
		models.DeviceExpired,
		models.DeviceRevoked,
		models.DeviceDecommissioned,
	}

	for _, status := range allStatus {
		nmbr, err := svc.devicesStorage.CountByStatus(context.Background(), status)
		if err != nil {
			lDevice.Errorf("could not count devices in %s status: %s", status, err)
			stats.DevicesStatus[status] = -1
		} else {
			stats.DevicesStatus[status] = nmbr
		}
	}

	nmbr, err := svc.devicesStorage.Count(context.Background())
	if err != nil {
		lDevice.Errorf("could not count devices: %s", err)
		stats.TotalDevices = -1
	} else {
		stats.TotalDevices = nmbr
	}

	return &stats, nil
}

type CreateDeviceInput struct {
	ID        string `validate:"required"`
	Alias     string
	Tags      []string
	Metadata  map[string]any
	DMSID     string `validate:"required"`
	Icon      string `validate:"required"`
	IconColor string `validate:"required"`
}

func (svc DeviceManagerServiceImpl) CreateDevice(input CreateDeviceInput) (*models.Device, error) {
	err := deviceValidate.Struct(input)
	if err != nil {
		lDevice.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	if input.Metadata == nil {
		input.Metadata = map[string]any{}
	}

	if input.Tags == nil {
		input.Tags = []string{}
	}

	lDevice.Debugf("creating %s device", input.ID)
	now := time.Now()

	device := &models.Device{
		ID:                input.ID,
		IdentitySlot:      nil,
		Status:            models.DeviceNoIdentity,
		ExtraSlots:        map[string]*models.Slot[any]{},
		Tags:              input.Tags,
		Metadata:          input.Metadata,
		Icon:              input.Icon,
		IconColor:         input.IconColor,
		DMSOwner:          input.DMSID,
		CreationTimestamp: now,
		Events: map[time.Time]models.DeviceEvent{
			now: {
				EvenType:          models.DeviceEventTypeCreated,
				EventDescriptions: "",
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
	resources.ListInput[models.Device]
}

func (svc DeviceManagerServiceImpl) GetDevices(input GetDevicesInput) (string, error) {
	lDevice.Debugf("getting all devices")
	return svc.devicesStorage.SelectAll(context.Background(), input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, nil)
}

type GetDevicesByDMSInput struct {
	DMSID string
	resources.ListInput[models.Device]
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

	if device.Status == input.NewStatus {
		lDevice.Warnf("skipping update. Device already in %s status", input.NewStatus)
		return device, nil
	} else if device.Status == models.DeviceDecommissioned {
		lDevice.Warnf("skipping update. Device decommissioned")
		return device, nil
	}

	if input.NewStatus == models.DeviceDecommissioned {
		if device.IdentitySlot.Status == models.SlotExpired {
			lDevice.Debugf("skipping slot update. Identity slot already expired")
		} else if device.IdentitySlot.Status == models.SlotRevoke {
			lDevice.Debugf("skipping slot update. Identity slot already revoked")
		} else {
			device.Events[time.Now()] = models.DeviceEvent{
				EvenType: models.DeviceEventTypeStatusDecommissioned,
			}
			slot := device.IdentitySlot
			slot.Status = models.SlotRevoke
			//don't revoke IdSlot, this will be handled by revoking the attached certificate
			_, err = svc.caClient.UpdateCertificateStatus(context.Background(), UpdateCertificateStatusInput{
				SerialNumber:     slot.Secrets[slot.ActiveVersion],
				NewStatus:        models.StatusRevoked,
				RevocationReason: ocsp.CessationOfOperation,
			})

			if err != nil {
				lDevice.Errorf("error while updating IdentitySlot from device %s to revoked. could not update certificate %s status: %s", device.ID, slot.Secrets[slot.ActiveVersion], err)
				return nil, err
			}
		}
	} else {
		device.Events[time.Now()] = models.DeviceEvent{
			EvenType:          models.DeviceEventTypeStatusUpdated,
			EventDescriptions: fmt.Sprintf("Status updated from '%s' to '%s'", device.Status, input.NewStatus),
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

	if device.Status == models.DeviceDecommissioned {
		lDevice.Warnf("device %s is decommissioned", input.ID)
		return device, nil
	}

	newSlot := input.Slot
	var newDevStatus models.DeviceStatus
	switch input.Slot.Status {
	case models.SlotRevoke:
		sn := device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion]
		crt, err := svc.caClient.GetCertificateBySerialNumber(context.Background(), GetCertificatesBySerialNumberInput{
			SerialNumber: sn,
		})
		if err != nil {
			lDevice.Errorf("could not get identity slot for device %s: %s", input.ID, err)
			return nil, err
		}

		if crt.Status != models.StatusRevoked {
			_, err = svc.caClient.UpdateCertificateStatus(context.Background(), UpdateCertificateStatusInput{
				SerialNumber:     sn,
				NewStatus:        models.StatusRevoked,
				RevocationReason: ocsp.Unspecified,
			})
			if err != nil {
				lDevice.Errorf("could not revoke identity slot for device %s: %s", input.ID, err)
				return nil, err
			}

		}
		newDevStatus = models.DeviceRevoked
	case models.SlotActive:
		newDevStatus = models.DeviceActive
	case models.SlotRenewalWindow:
		newDevStatus = models.DeviceRenewalWindow
	case models.SlotAboutToExpire:
		newDevStatus = models.DeviceAboutToExpire
	case models.SlotExpired:
		newDevStatus = models.DeviceExpired
	}

	if device.IdentitySlot != nil && newSlot.Status != device.IdentitySlot.Status {
		newSlot.Events[time.Now()] = models.DeviceEvent{
			EvenType:          models.DeviceEventTypeStatusUpdated,
			EventDescriptions: fmt.Sprintf("Identity Slot Status updated from '%s' to '%s'", device.Status, newSlot.Status),
		}
	}
	device.IdentitySlot = &newSlot

	lDevice.Debugf("updating %s device identity slot. New device status %s. ID slot status %s", input.ID, device.Status, device.IdentitySlot.Status)
	device, err = svc.devicesStorage.Update(context.Background(), device)
	if err != nil {
		return nil, err
	}

	if device.Status != newDevStatus {
		device, err = svc.service.UpdateDeviceStatus(UpdateDeviceStatusInput{
			ID:        device.ID,
			NewStatus: newDevStatus,
		})
		if err != nil {
			lDevice.Errorf("could not update device %s status to %s: %s", input.ID, newDevStatus, err)
			return nil, err
		}
	}

	return device, nil
}
