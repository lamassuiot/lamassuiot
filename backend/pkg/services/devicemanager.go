package services

import (
	"context"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

var deviceValidate *validator.Validate

type DeviceMiddleware func(services.DeviceManagerService) services.DeviceManagerService

type DeviceManagerServiceBackend struct {
	devicesStorage storage.DeviceManagerRepo
	eventStore     storage.DeviceEventsRepo
	statusStore    storage.DeviceStatusRepo
	caClient       services.CAService
	service        services.DeviceManagerService
	logger         *logrus.Entry
}

type DeviceManagerBuilder struct {
	Logger         *logrus.Entry
	CAClient       services.CAService
	DevicesStorage storage.DeviceManagerRepo
	EventsStorage  storage.DeviceEventsRepo
	StatusStorage  storage.DeviceStatusRepo
}

func NewDeviceManagerService(builder DeviceManagerBuilder) services.DeviceManagerService {
	deviceValidate = validator.New()
	svc := &DeviceManagerServiceBackend{
		caClient:       builder.CAClient,
		devicesStorage: builder.DevicesStorage,
		eventStore:     builder.EventsStorage,
		statusStore:    builder.StatusStorage,
		logger:         builder.Logger,
	}

	svc.service = svc
	return svc
}

func (svc *DeviceManagerServiceBackend) SetService(service services.DeviceManagerService) {
	svc.service = service
}

func (svc *DeviceManagerServiceBackend) GetDevicesStats(ctx context.Context, input services.GetDevicesStatsInput) (*models.DevicesStats, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	// Validate that status filters are not provided
	if input.QueryParameters != nil {
		for _, filter := range input.QueryParameters.Filters {
			if filter.Field == "status" {
				lFunc.Errorf("status filter is not allowed in GetDevicesStats")
				return nil, errs.ErrValidateBadRequest
			}
		}
	}

	stats := models.DevicesStats{
		TotalDevices:  -1,
		DevicesStatus: map[models.DeviceStatusType]int{},
	}

	allStatus := []models.DeviceStatusType{
		models.DeviceStatusOK,
		models.DeviceStatusWarn,
		models.DeviceStatusError,
		models.DeviceStatusDecommissioned,
	}

	for _, status := range allStatus {
		// Build query parameters with status filter added
		statusQueryParams := addStatusFilter(input.QueryParameters, status)
		nmbr, err := svc.devicesStorage.Count(ctx, statusQueryParams)
		if err != nil {
			lFunc.Errorf("could not count devices in %s status: %s", status, err)
			stats.DevicesStatus[status] = -1
		} else {
			stats.DevicesStatus[status] = nmbr
		}
	}

	nmbr, err := svc.devicesStorage.Count(ctx, input.QueryParameters)
	if err != nil {
		lFunc.Errorf("could not count devices: %s", err)
		stats.TotalDevices = -1
	} else {
		stats.TotalDevices = nmbr
	}

	return &stats, nil
}

// addStatusFilter creates a new QueryParameters with the status filter added.
// This is used to count devices by status while preserving other filters.
func addStatusFilter(queryParams *resources.QueryParameters, status models.DeviceStatusType) *resources.QueryParameters {
	// If queryParams is nil, create a new one with just the status filter
	if queryParams == nil {
		return &resources.QueryParameters{
			Filters: []resources.FilterOption{
				{
					Field:           "status",
					FilterOperation: resources.EnumEqual,
					Value:           string(status),
				},
			},
		}
	}

	// Create a copy of the existing query parameters
	statusQueryParams := &resources.QueryParameters{
		Sort:         queryParams.Sort,
		PageSize:     queryParams.PageSize,
		NextBookmark: queryParams.NextBookmark,
		Filters:      make([]resources.FilterOption, 0, len(queryParams.Filters)+1),
	}

	// Copy existing filters, removing any existing status filters to avoid conflicts
	for _, filter := range queryParams.Filters {
		if filter.Field != "status" {
			statusQueryParams.Filters = append(statusQueryParams.Filters, filter)
		}
	}

	// Add the new status filter
	statusQueryParams.Filters = append(statusQueryParams.Filters, resources.FilterOption{
		Field:           "status",
		FilterOperation: resources.EnumEqual,
		Value:           string(status),
	})

	return statusQueryParams
}

func (svc DeviceManagerServiceBackend) CreateDevice(ctx context.Context, input services.CreateDeviceInput) (*models.Device, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

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
		Status:            models.DeviceStatusOK,
		ExtraSlots:        map[string]*models.Slot[any]{},
		Tags:              input.Tags,
		Metadata:          input.Metadata,
		Icon:              input.Icon,
		IconColor:         input.IconColor,
		DMSOwner:          input.DMSID,
		CreationTimestamp: now,
	}

	event := models.DeviceEvent{
		DeviceID:  input.ID,
		Type:      string(models.DeviceEventTypeLifecycleStatusUpdated),
		Message:   "device created",
		Timestamp: now,
		SlotID:    "",
		Source:    models.DeviceManagerSource,
		StructuredField: map[string]string{
			"previous_status": string(""),
			"new_status":      string(device.Status),
		},
	}

	status := models.DeviceStatus{
		DeviceID:   input.ID,
		Status:     device.Status,
		UpdateTime: now,
	}

	dev, err := svc.devicesStorage.Insert(ctx, device)
	if err != nil {
		lFunc.Errorf("could not insert device %s in storage engine: %s", input.ID, err)
		return nil, err
	}

	_, err = svc.eventStore.Insert(ctx, &event)
	if err != nil {
		lFunc.Warnf("could not insert device event for device %s: %s", input.ID, err)
	}

	_, err = svc.statusStore.Insert(ctx, &status)
	if err != nil {
		lFunc.Warnf("could not insert device status for device %s: %s", input.ID, err)
	}

	return dev, nil
}

func (svc DeviceManagerServiceBackend) GetDevices(ctx context.Context, input services.GetDevicesInput) (string, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Debugf("getting all devices")
	return svc.devicesStorage.SelectAll(ctx, input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, nil)
}

func (svc DeviceManagerServiceBackend) GetDeviceByDMS(ctx context.Context, input services.GetDevicesByDMSInput) (string, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Debugf("getting all devices owned by DMS with ID=%s", input.DMSID)
	return svc.devicesStorage.SelectByDMS(ctx, input.DMSID, input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, nil)
}

func (svc DeviceManagerServiceBackend) GetDeviceByID(ctx context.Context, input services.GetDeviceByIDInput) (*models.Device, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

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

func (svc DeviceManagerServiceBackend) UpdateDeviceStatus(ctx context.Context, input services.UpdateDeviceStatusInput) (*models.Device, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

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
	} else if device.Status == models.DeviceStatusDecommissioned {
		lFunc.Warnf("skipping update. Device decommissioned")
		return device, nil
	}

	newEvent := models.DeviceEvent{
		DeviceID:  input.ID,
		Type:      string(models.DeviceEventTypeLifecycleStatusUpdated),
		Message:   fmt.Sprintf("device status updated from '%s' to '%s'", device.Status, input.NewStatus),
		Timestamp: time.Now(),
		SlotID:    "",
		Source:    models.DeviceManagerSource,
		StructuredField: map[string]string{
			"previous_status": string(device.Status),
			"new_status":      string(input.NewStatus),
		},
	}

	newStatus := models.DeviceStatus{
		DeviceID:   input.ID,
		Status:     input.NewStatus,
		UpdateTime: time.Now(),
	}

	if input.NewStatus == models.DeviceStatusDecommissioned {
		idSlot := device.IdentitySlot
		if idSlot != nil {
			if idSlot.Status == string(models.SlotX509StatusExpired) {
				lFunc.Debugf("skipping slot update. Identity slot already expired")
			} else if idSlot.Status == string(models.SlotX509StatusRevoked) {
				lFunc.Debugf("skipping slot update. Identity slot already revoked")
			} else {

				idSlot.Status = string(models.SlotX509StatusRevoked)
				defer func() {
					certSN := idSlot.Secrets[idSlot.ActiveVersion]
					//don't revoke IdSlot, this will be handled by revoking the attached certificate
					_, err = svc.caClient.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
						SerialNumber:     certSN,
						NewStatus:        models.StatusRevoked,
						RevocationReason: ocsp.CessationOfOperation,
					})

					if err != nil {
						lFunc.Errorf("error while updating IdentitySlot from device %s to revoked. could not update certificate %s status: %s", device.ID, certSN, err)
						return
					}
				}()
			}
		}
	}

	device.Status = input.NewStatus
	lFunc.Debugf("updating %s device status to %s", input.ID, input.NewStatus)
	device, err = svc.devicesStorage.Update(ctx, device)
	if err != nil {
		lFunc.Errorf("error while updating %s device status. could not update DB: %s", device.ID, err)
		return nil, err
	}

	_, err = svc.eventStore.Insert(ctx, &newEvent)
	if err != nil {
		lFunc.Warnf("error while inserting device event for device %s: %s", device.ID, err)
	}

	_, err = svc.statusStore.Insert(ctx, &newStatus)
	if err != nil {
		lFunc.Warnf("error while inserting device status for device %s: %s", device.ID, err)
	}

	lFunc.Debugf("device %s status updated. new status: %s", input.ID, input.NewStatus)
	return device, nil
}

func (svc DeviceManagerServiceBackend) UpdateDeviceMetadata(ctx context.Context, input services.UpdateDeviceMetadataInput) (*models.Device, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

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
		return nil, errs.ErrDeviceNotFound
	}

	updatedMetadata, err := chelpers.ApplyPatches[map[string]any](device.Metadata, input.Patches)
	if err != nil {
		lFunc.Errorf("failed to apply patches to metadata for Device '%s': %v", input.ID, err)
		return nil, err
	}

	device.Metadata = *updatedMetadata

	lFunc.Debugf("updating %s device metadata", input.ID)
	return svc.devicesStorage.Update(ctx, device)

}

func (svc DeviceManagerServiceBackend) UpdateDeviceIdentitySlot(ctx context.Context, input services.UpdateDeviceIdentitySlotInput) (*models.Device, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

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

	if device.Status == models.DeviceStatusDecommissioned {
		lFunc.Warnf("device %s is decommissioned", input.ID)
		return device, nil
	}

	newSlot := input.Slot

	var newDevStatus models.DeviceStatusType

	switch input.Slot.Status {
	case string(models.SlotX509StatusRevoked):
		sn := device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion]
		crt, err := svc.caClient.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
			SerialNumber: sn,
		})
		if err != nil {
			lFunc.Errorf("could not get identity slot for device %s: %s", input.ID, err)
			return nil, err
		}

		if crt.Status != models.StatusRevoked {
			_, err = svc.caClient.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
				SerialNumber:     sn,
				NewStatus:        models.StatusRevoked,
				RevocationReason: ocsp.Unspecified,
			})
			if err != nil {
				lFunc.Errorf("could not revoke identity slot for device %s: %s", input.ID, err)
				return nil, err
			}

		}

		newDevStatus = models.DeviceStatusError

	case string(models.SlotX509StatusActive):
		newDevStatus = models.DeviceStatusOK

	case string(models.SlotX509StatusRenewalWindow):
		newDevStatus = models.DeviceStatusWarn

	case string(models.SlotX509StatusAboutToExpire):
		newDevStatus = models.DeviceStatusWarn

	case string(models.SlotX509StatusExpired):
		newDevStatus = models.DeviceStatusError
	}

	if device.IdentitySlot != nil && newSlot.Status != device.IdentitySlot.Status {
		newEvent := models.DeviceEvent{
			DeviceID:        input.ID,
			Type:            string(models.DeviceEventTypeIDSlotStatusUpdated),
			Message:         fmt.Sprintf("identity slot status updated from '%s' to '%s'", device.IdentitySlot.Status, newSlot.Status),
			Timestamp:       time.Now(),
			SlotID:          "idslot",
			Source:          models.DeviceManagerSource,
			StructuredField: nil,
		}

		_, err := svc.eventStore.Insert(ctx, &newEvent)
		if err != nil {
			lFunc.Errorf("could not insert device event for device %s: %s", input.ID, err)
			return nil, err
		}

		if newDevStatus != device.Status {
			_, err := svc.service.UpdateDeviceStatus(ctx, services.UpdateDeviceStatusInput{
				ID:        input.ID,
				NewStatus: newDevStatus,
			})
			if err != nil {
				lFunc.Errorf("could not update device %s status to %s: %s", input.ID, newDevStatus, err)
				return nil, err
			}
		}
	}

	device.IdentitySlot = &newSlot

	lFunc.Debugf("updating %s device identity slot. New device status %s. ID slot status %s", input.ID, device.Status, device.IdentitySlot.Status)
	device, err = svc.devicesStorage.Update(ctx, device)
	if err != nil {
		return nil, err
	}

	if device.Status != newDevStatus {
		device, err = svc.service.UpdateDeviceStatus(ctx, services.UpdateDeviceStatusInput{
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

func (svc DeviceManagerServiceBackend) DeleteDevice(ctx context.Context, input services.DeleteDeviceInput) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := deviceValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return errs.ErrValidateBadRequest
	}

	id := input.ID
	lFunc.Debugf("checking if device '%s' exists", id)
	exists, device, err := svc.devicesStorage.SelectExists(ctx, id)
	if err != nil {
		lFunc.Errorf("something went wrong while checking if device '%s' exists in storage engine: %s", id, err)
		return err
	} else if !exists {
		lFunc.Errorf("device '%s' does not exist in storage engine", id)
		return errs.ErrDeviceNotFound
	}

	// Only allow deletion of decommissioned devices
	if device.Status != models.DeviceStatusDecommissioned {
		lFunc.Errorf("cannot delete device '%s': device must be decommissioned first. Current status: %s", id, device.Status)
		return errs.ErrDeviceInvalidStatus
	}

	lFunc.Debugf("deleting device '%s'", id)
	err = svc.devicesStorage.Delete(ctx, id)
	if err != nil {
		lFunc.Errorf("something went wrong while deleting device '%s' from storage engine: %s", id, err)
		return err
	}

	lFunc.Infof("device '%s' deleted successfully", id)
	return nil
}

func (svc DeviceManagerServiceBackend) CreateDeviceEvent(ctx context.Context, input services.CreateDeviceEventInput) (*models.DeviceEvent, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	ev, err := svc.eventStore.Insert(ctx, &input.Event)
	if err != nil {
		lFunc.Errorf("could not insert device event for device %s: %s", input.Event.DeviceID, err)
		return nil, err
	}

	return ev, nil
}

func (svc DeviceManagerServiceBackend) GetDeviceEvents(ctx context.Context, input services.GetDeviceEventsInput) (string, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Debugf("getting all events for device %s", input.DeviceID)
	return svc.eventStore.Select(ctx, input.DeviceID, input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, nil)
}
