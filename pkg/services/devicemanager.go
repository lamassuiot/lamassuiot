package services

import (
	"context"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/v2/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
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
	GetDevicesStats(ctx context.Context, input GetDevicesStatsInput) (*models.DevicesStats, error)
	CreateDevice(ctx context.Context, input CreateDeviceInput) (*models.Device, error)
	GetDeviceByID(ctx context.Context, input GetDeviceByIDInput) (*models.Device, error)
	GetDevices(ctx context.Context, input GetDevicesInput) (string, error)
	GetDeviceByDMS(ctx context.Context, input GetDevicesByDMSInput) (string, error)
	UpdateDeviceStatus(ctx context.Context, input UpdateDeviceStatusInput) (*models.Device, error)
	UpdateDeviceIdentitySlot(ctx context.Context, input UpdateDeviceIdentitySlotInput) (*models.Device, error)
	UpdateDeviceMetadata(ctx context.Context, input UpdateDeviceMetadataInput) (*models.Device, error)
}

type DeviceManagerServiceBackend struct {
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
	svc := &DeviceManagerServiceBackend{
		caClient:       builder.CAClient,
		devicesStorage: builder.DevicesStorage,
	}

	svc.service = svc
	return svc
}

func (svc *DeviceManagerServiceBackend) SetService(service DeviceManagerService) {
	svc.service = service
}

type GetDevicesStatsInput struct {
}

func (svc *DeviceManagerServiceBackend) GetDevicesStats(ctx context.Context, input GetDevicesStatsInput) (*models.DevicesStats, error) {
	lFunc := helpers.ConfigureLogger(ctx, lCA)

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
		nmbr, err := svc.devicesStorage.CountByStatus(ctx, status)
		if err != nil {
			lFunc.Errorf("could not count devices in %s status: %s", status, err)
			stats.DevicesStatus[status] = -1
		} else {
			stats.DevicesStatus[status] = nmbr
		}
	}

	nmbr, err := svc.devicesStorage.Count(ctx)
	if err != nil {
		lFunc.Errorf("could not count devices: %s", err)
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

func (svc DeviceManagerServiceBackend) CreateDevice(ctx context.Context, input CreateDeviceInput) (*models.Device, error) {
	lFunc := helpers.ConfigureLogger(ctx, lCA)

	err := deviceValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	if input.Metadata == nil {
		input.Metadata = map[string]any{}
	}

	if input.Tags == nil {
		input.Tags = []string{}
	}

	lFunc.Debugf("creating %s device", input.ID)
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

	dev, err := svc.devicesStorage.Insert(ctx, device)
	if err != nil {
		lFunc.Errorf("could not insert device %s in storage engine: %s", input.ID, err)
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

func (svc DeviceManagerServiceBackend) GetDevices(ctx context.Context, input GetDevicesInput) (string, error) {
	lFunc := helpers.ConfigureLogger(ctx, lCA)

	lFunc.Debugf("getting all devices")
	return svc.devicesStorage.SelectAll(ctx, input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, nil)
}

type GetDevicesByDMSInput struct {
	DMSID string
	resources.ListInput[models.Device]
}

func (svc DeviceManagerServiceBackend) GetDeviceByDMS(ctx context.Context, input GetDevicesByDMSInput) (string, error) {
	lFunc := helpers.ConfigureLogger(ctx, lCA)

	lFunc.Debugf("getting all devices owned by DMS with ID=%s", input.DMSID)
	return svc.devicesStorage.SelectByDMS(ctx, input.DMSID, input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, nil)
}

type GetDeviceByIDInput struct {
	ID string `validate:"required"`
}

func (svc DeviceManagerServiceBackend) GetDeviceByID(ctx context.Context, input GetDeviceByIDInput) (*models.Device, error) {
	lFunc := helpers.ConfigureLogger(ctx, lCA)

	err := deviceValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}
	lFunc.Debugf("checking if device '%s' exists", input.ID)
	exists, device, err := svc.devicesStorage.SelectExists(ctx, input.ID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if device '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	} else if !exists {
		lFunc.Errorf("device %s can not be found in storage engine", input.ID)
		return nil, errs.ErrDeviceNotFound
	}

	return device, nil
}

type UpdateDeviceStatusInput struct {
	ID        string              `validate:"required"`
	NewStatus models.DeviceStatus `validate:"required"`
}

func (svc DeviceManagerServiceBackend) UpdateDeviceStatus(ctx context.Context, input UpdateDeviceStatusInput) (*models.Device, error) {
	lFunc := helpers.ConfigureLogger(ctx, lCA)

	err := deviceValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}
	lFunc.Debugf("checking if device '%s' exists", input.ID)
	exists, device, err := svc.devicesStorage.SelectExists(ctx, input.ID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if device '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	} else if !exists {
		lFunc.Errorf("device %s can not be found in storage engine", input.ID)
		return nil, errs.ErrDeviceNotFound
	}

	if device.Status == input.NewStatus {
		lFunc.Warnf("skipping update. Device already in %s status", input.NewStatus)
		return device, nil
	} else if device.Status == models.DeviceDecommissioned {
		lFunc.Warnf("skipping update. Device decommissioned")
		return device, nil
	}

	if input.NewStatus == models.DeviceDecommissioned {
		if device.IdentitySlot.Status == models.SlotExpired {
			lFunc.Debugf("skipping slot update. Identity slot already expired")
		} else if device.IdentitySlot.Status == models.SlotRevoke {
			lFunc.Debugf("skipping slot update. Identity slot already revoked")
		} else {
			device.Events[time.Now()] = models.DeviceEvent{
				EvenType: models.DeviceEventTypeStatusDecommissioned,
			}
			slot := device.IdentitySlot
			slot.Status = models.SlotRevoke
			//don't revoke IdSlot, this will be handled by revoking the attached certificate
			_, err = svc.caClient.UpdateCertificateStatus(ctx, UpdateCertificateStatusInput{
				SerialNumber:     slot.Secrets[slot.ActiveVersion],
				NewStatus:        models.StatusRevoked,
				RevocationReason: ocsp.CessationOfOperation,
			})

			if err != nil {
				lFunc.Errorf("error while updating IdentitySlot from device %s to revoked. could not update certificate %s status: %s", device.ID, slot.Secrets[slot.ActiveVersion], err)
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
	lFunc.Debugf("updating %s device status to %s", input.ID, input.NewStatus)
	device, err = svc.devicesStorage.Update(ctx, device)
	if err != nil {
		lFunc.Errorf("error while updating %s device status. could not update DB: %s", device.ID, err)
		return nil, err
	}

	lFunc.Debugf("device %s status updated. new status: %s", input.ID, input.NewStatus)
	return device, nil
}

type UpdateDeviceMetadataInput struct {
	ID       string         `validate:"required"`
	Metadata map[string]any `validate:"required"`
}

func (svc DeviceManagerServiceBackend) UpdateDeviceMetadata(ctx context.Context, input UpdateDeviceMetadataInput) (*models.Device, error) {
	lFunc := helpers.ConfigureLogger(ctx, lCA)

	err := deviceValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("UpdateDeviceMetadata struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	lFunc.Debugf("checking if device '%s' exists", input.ID)
	exists, device, err := svc.devicesStorage.SelectExists(ctx, input.ID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if device '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("device %s can not be found in storage engine", input.ID)
		return nil, err
	}

	device.Metadata = input.Metadata

	lFunc.Debugf("updating %s device metadata", input.ID)
	return svc.devicesStorage.Update(ctx, device)

}

type UpdateDeviceIdentitySlotInput struct {
	ID   string              `validate:"required"`
	Slot models.Slot[string] `validate:"required"`
}

func (svc DeviceManagerServiceBackend) UpdateDeviceIdentitySlot(ctx context.Context, input UpdateDeviceIdentitySlotInput) (*models.Device, error) {
	lFunc := helpers.ConfigureLogger(ctx, lCA)

	err := deviceValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}
	lFunc.Debugf("checking if device '%s' exists", input.ID)
	exists, device, err := svc.devicesStorage.SelectExists(ctx, input.ID)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if device '%s' exists in storage engine: %s", input.ID, err)
		return nil, err
	} else if !exists {
		lFunc.Errorf("device %s can not be found in storage engine", input.ID)
		return nil, errs.ErrDeviceNotFound
	}

	if device.Status == models.DeviceDecommissioned {
		lFunc.Warnf("device %s is decommissioned", input.ID)
		return device, nil
	}

	newSlot := input.Slot
	var newDevStatus models.DeviceStatus
	switch input.Slot.Status {
	case models.SlotRevoke:
		sn := device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion]
		crt, err := svc.caClient.GetCertificateBySerialNumber(ctx, GetCertificatesBySerialNumberInput{
			SerialNumber: sn,
		})
		if err != nil {
			lFunc.Errorf("could not get identity slot for device %s: %s", input.ID, err)
			return nil, err
		}

		if crt.Status != models.StatusRevoked {
			_, err = svc.caClient.UpdateCertificateStatus(ctx, UpdateCertificateStatusInput{
				SerialNumber:     sn,
				NewStatus:        models.StatusRevoked,
				RevocationReason: ocsp.Unspecified,
			})
			if err != nil {
				lFunc.Errorf("could not revoke identity slot for device %s: %s", input.ID, err)
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

	lFunc.Debugf("updating %s device identity slot. New device status %s. ID slot status %s", input.ID, device.Status, device.IdentitySlot.Status)
	device, err = svc.devicesStorage.Update(ctx, device)
	if err != nil {
		return nil, err
	}

	if device.Status != newDevStatus {
		device, err = svc.service.UpdateDeviceStatus(ctx, UpdateDeviceStatusInput{
			ID:        device.ID,
			NewStatus: newDevStatus,
		})
		if err != nil {
			lFunc.Errorf("could not update device %s status to %s: %s", input.ID, newDevStatus, err)
			return nil, err
		}
	}

	return device, nil
}
