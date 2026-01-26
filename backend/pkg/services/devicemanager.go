package services

import (
	"context"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
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
	caClient       services.CAService
	service        services.DeviceManagerService
	logger         *logrus.Entry
}

type DeviceManagerBuilder struct {
	Logger         *logrus.Entry
	CAClient       services.CAService
	DevicesStorage storage.DeviceManagerRepo
}

func NewDeviceManagerService(builder DeviceManagerBuilder) services.DeviceManagerService {
	deviceValidate = validator.New()
	svc := &DeviceManagerServiceBackend{
		caClient:       builder.CAClient,
		devicesStorage: builder.DevicesStorage,
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
func addStatusFilter(queryParams *resources.QueryParameters, status models.DeviceStatus) *resources.QueryParameters {
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
	} else if device.Status == models.DeviceDecommissioned {
		lFunc.Warnf("skipping update. Device decommissioned")
		return device, nil
	}

	if input.NewStatus == models.DeviceDecommissioned {

		device.Events[time.Now()] = models.DeviceEvent{
			EvenType: models.DeviceEventTypeStatusDecommissioned,
		}

		idSlot := device.IdentitySlot
		if idSlot != nil {
			if idSlot.Status == models.SlotExpired {
				lFunc.Debugf("skipping slot update. Identity slot already expired")
			} else if idSlot.Status == models.SlotRevoke {
				lFunc.Debugf("skipping slot update. Identity slot already revoked")
			} else {

				idSlot.Status = models.SlotRevoke
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

	if device.Status == models.DeviceDecommissioned {
		lFunc.Warnf("device %s is decommissioned", input.ID)
		return device, nil
	}

	newSlot := input.Slot
	var newDevStatus models.DeviceStatus
	switch input.Slot.Status {
	case models.SlotRevoke:
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
	if device.Status != models.DeviceDecommissioned {
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

// ============================================================================
// Device Group Operations
// ============================================================================

func (svc DeviceManagerServiceBackend) CreateDeviceGroup(ctx context.Context, input services.CreateDeviceGroupInput) (*models.DeviceGroup, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := deviceValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	// Validate criteria fields
	if err := svc.validateCriteriaFields(lFunc, input.Criteria); err != nil {
		return nil, err
	}

	// Validate parent reference
	if err := svc.validateParentReference(ctx, lFunc, input.ID, input.ParentID); err != nil {
		return nil, err
	}

	// Convert criteria to model format
	criteria := convertInputCriteria(input.Criteria)

	now := time.Now()
	group := &models.DeviceGroup{
		ID:          input.ID,
		Name:        input.Name,
		Description: input.Description,
		ParentID:    input.ParentID,
		Criteria:    criteria,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	lFunc.Debugf("creating device group '%s'", input.ID)
	group, err = svc.devicesStorage.DeviceGroups().Insert(ctx, group)
	if err != nil {
		lFunc.Errorf("could not insert device group '%s' in storage engine: %s", input.ID, err)
		return nil, err
	}

	lFunc.Infof("device group '%s' created successfully", input.ID)

	// Enrich with ancestor criteria
	if err := svc.enrichGroupWithAncestorCriteria(ctx, lFunc, group); err != nil {
		return nil, err
	}

	return group, nil
}

func (svc DeviceManagerServiceBackend) UpdateDeviceGroup(ctx context.Context, input services.UpdateDeviceGroupInput) (*models.DeviceGroup, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := deviceValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	// Verify group exists
	group, err := svc.verifyGroupExists(ctx, lFunc, input.ID)
	if err != nil {
		return nil, err
	}

	// Update fields if provided
	if input.Name != "" {
		group.Name = input.Name
	}
	if input.Description != "" {
		group.Description = input.Description
	}

	// Update ParentID if provided
	if input.ParentID != nil {
		if err := svc.validateParentReference(ctx, lFunc, input.ID, input.ParentID); err != nil {
			return nil, err
		}
		group.ParentID = input.ParentID
	}

	// Update Criteria if provided
	if len(input.Criteria) > 0 {
		if err := svc.validateCriteriaFields(lFunc, input.Criteria); err != nil {
			return nil, err
		}
		group.Criteria = convertInputCriteria(input.Criteria)
	}

	group.UpdatedAt = time.Now()

	lFunc.Debugf("updating device group '%s'", input.ID)
	group, err = svc.devicesStorage.DeviceGroups().Update(ctx, group)
	if err != nil {
		lFunc.Errorf("could not update device group '%s' in storage engine: %s", input.ID, err)
		return nil, err
	}

	lFunc.Infof("device group '%s' updated successfully", input.ID)

	// Enrich with ancestor criteria
	if err := svc.enrichGroupWithAncestorCriteria(ctx, lFunc, group); err != nil {
		return nil, err
	}

	return group, nil
}

func (svc DeviceManagerServiceBackend) DeleteDeviceGroup(ctx context.Context, input services.DeleteDeviceGroupInput) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := deviceValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return errs.ErrValidateBadRequest
	}

	// Verify group exists
	if _, err := svc.verifyGroupExists(ctx, lFunc, input.ID); err != nil {
		return err
	}

	lFunc.Debugf("deleting device group '%s'", input.ID)
	err = svc.devicesStorage.DeviceGroups().Delete(ctx, input.ID)
	if err != nil {
		lFunc.Errorf("could not delete device group '%s' from storage engine: %s", input.ID, err)
		return err
	}

	lFunc.Infof("device group '%s' deleted successfully", input.ID)
	return nil
}

func (svc DeviceManagerServiceBackend) GetDeviceGroupByID(ctx context.Context, input services.GetDeviceGroupByIDInput) (*models.DeviceGroup, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := deviceValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	// Get device group
	lFunc.Debugf("getting device group '%s'", input.ID)
	group, err := svc.verifyGroupExists(ctx, lFunc, input.ID)
	if err != nil {
		return nil, err
	}

	// Enrich with ancestor criteria
	if err := svc.enrichGroupWithAncestorCriteria(ctx, lFunc, group); err != nil {
		return nil, err
	}

	return group, nil
}

func (svc DeviceManagerServiceBackend) GetDeviceGroups(ctx context.Context, input services.GetDeviceGroupsInput) (string, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Debugf("getting all device groups")
	return svc.devicesStorage.DeviceGroups().SelectAll(ctx, storage.StorageListRequest[models.DeviceGroup]{
		ExhaustiveRun: input.ExhaustiveRun,
		ApplyFunc:     input.ApplyFunc,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     nil,
	})
}

func (svc DeviceManagerServiceBackend) GetDevicesByGroup(ctx context.Context, input services.GetDevicesByGroupInput) (string, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := deviceValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return "", errs.ErrValidateBadRequest
	}

	// Verify group exists
	lFunc.Debugf("fetching device group '%s'", input.GroupID)
	if _, err := svc.verifyGroupExists(ctx, lFunc, input.GroupID); err != nil {
		return "", err
	}

	// Get the parent chain (ancestors) including the group itself
	lFunc.Debugf("resolving hierarchy for device group '%s'", input.GroupID)
	ancestors, err := svc.devicesStorage.DeviceGroups().SelectAncestors(ctx, input.GroupID)
	if err != nil {
		lFunc.Errorf("could not get ancestors for device group '%s': %s", input.GroupID, err)
		return "", err
	}

	// Compose merged filters from all groups' criteria
	composedFilters := svc.composeFiltersFromHierarchy(ancestors, input.QueryParameters)

	// Call existing GetDevices with composed filters
	lFunc.Debugf("fetching devices for group '%s' with %d composed filters", input.GroupID, len(composedFilters.Filters))
	return svc.service.GetDevices(ctx, services.GetDevicesInput{
		ListInput: resources.ListInput[models.Device]{
			ExhaustiveRun:   input.ExhaustiveRun,
			ApplyFunc:       input.ApplyFunc,
			QueryParameters: composedFilters,
		},
	})
}

func (svc DeviceManagerServiceBackend) GetDeviceGroupStats(ctx context.Context, input services.GetDeviceGroupStatsInput) (*models.DevicesStats, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := deviceValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	// Verify group exists
	lFunc.Debugf("fetching device group '%s'", input.GroupID)
	if _, err := svc.verifyGroupExists(ctx, lFunc, input.GroupID); err != nil {
		return nil, err
	}

	// Get the parent chain (ancestors) including the group itself
	lFunc.Debugf("resolving hierarchy for device group '%s'", input.GroupID)
	ancestors, err := svc.devicesStorage.DeviceGroups().SelectAncestors(ctx, input.GroupID)
	if err != nil {
		lFunc.Errorf("could not get ancestors for device group '%s': %s", input.GroupID, err)
		return nil, err
	}

	// Compose merged filters from all groups' criteria
	composedFilters := svc.composeFiltersFromHierarchy(ancestors, nil)

	// Call existing GetDevicesStats with composed filters
	lFunc.Debugf("calculating stats for group '%s' with %d composed filters", input.GroupID, len(composedFilters.Filters))
	return svc.service.GetDevicesStats(ctx, services.GetDevicesStatsInput{
		QueryParameters: composedFilters,
	})
}

// ============================================================================
// Helper Functions
// ============================================================================

// validateNoCircularReference checks if setting parentID would create a circular reference
func (svc DeviceManagerServiceBackend) validateNoCircularReference(ctx context.Context, groupID string, parentID string) error {
	// Cannot set self as parent
	if groupID == parentID {
		return errs.ErrDeviceGroupCircularReference
	}

	// Check if the proposed parent is a descendant of this group
	// by checking if groupID appears in the ancestor chain of parentID
	ancestors, err := svc.devicesStorage.DeviceGroups().SelectAncestors(ctx, parentID)
	if err != nil {
		return err
	}

	for _, ancestor := range ancestors {
		if ancestor.ID == groupID {
			return errs.ErrDeviceGroupCircularReference
		}
	}

	return nil
}

// composeFiltersFromHierarchy merges all criteria from ancestor groups
// The result is an implicit AND of all filters in the hierarchy
func (svc DeviceManagerServiceBackend) composeFiltersFromHierarchy(ancestors []*models.DeviceGroup, baseParams *resources.QueryParameters) *resources.QueryParameters {
	// Start with base parameters or create new
	var composedParams *resources.QueryParameters
	if baseParams != nil {
		// Create a copy to avoid modifying the input
		composedParams = &resources.QueryParameters{
			Sort:         baseParams.Sort,
			PageSize:     baseParams.PageSize,
			NextBookmark: baseParams.NextBookmark,
			Filters:      make([]resources.FilterOption, len(baseParams.Filters)),
		}
		copy(composedParams.Filters, baseParams.Filters)
	} else {
		composedParams = &resources.QueryParameters{
			Filters: make([]resources.FilterOption, 0),
		}
	}

	// Append all criteria from ancestors (root to leaf order)
	for _, group := range ancestors {
		for _, criterion := range group.Criteria {
			composedParams.Filters = append(composedParams.Filters, resources.FilterOption{
				Field:           criterion.Field,
				FilterOperation: resources.FilterOperation(criterion.FilterOperation),
				Value:           criterion.Value,
			})
		}
	}

	return composedParams
}

// validateCriteriaFields validates that all criteria fields are valid DeviceFilterableFields
func (svc DeviceManagerServiceBackend) validateCriteriaFields(lFunc *logrus.Entry, criteria []models.DeviceGroupFilterOption) error {
	for _, criterion := range criteria {
		if _, exists := resources.DeviceFilterableFields[criterion.Field]; !exists {
			lFunc.Errorf("invalid filter field '%s' in criteria. Must be a valid DeviceFilterableField", criterion.Field)
			return errs.ErrValidateBadRequest
		}
	}
	return nil
}

// convertInputCriteria converts input criteria to models.DeviceGroupFilterOption (currently a no-op as types match)
func convertInputCriteria(criteria []models.DeviceGroupFilterOption) []models.DeviceGroupFilterOption {
	// Since input already uses models.DeviceGroupFilterOption, just return a copy
	result := make([]models.DeviceGroupFilterOption, len(criteria))
	copy(result, criteria)
	return result
}

// verifyGroupExists checks if a device group exists and returns it
func (svc DeviceManagerServiceBackend) verifyGroupExists(ctx context.Context, lFunc *logrus.Entry, groupID string) (*models.DeviceGroup, error) {
	lFunc.Debugf("checking if device group '%s' exists", groupID)
	exists, group, err := svc.devicesStorage.DeviceGroups().SelectByID(ctx, groupID)
	if err != nil {
		lFunc.Errorf("could not verify device group existence: %s", err)
		return nil, err
	}
	if !exists {
		lFunc.Errorf("device group '%s' does not exist", groupID)
		return nil, errs.ErrDeviceGroupNotFound
	}
	return group, nil
}

// validateParentReference validates parent ID and checks for circular references
func (svc DeviceManagerServiceBackend) validateParentReference(ctx context.Context, lFunc *logrus.Entry, groupID string, parentID *string) error {
	if parentID == nil {
		return nil
	}

	// Check for self-reference
	if *parentID == groupID {
		lFunc.Errorf("device group cannot be its own parent")
		return errs.ErrDeviceGroupCircularReference
	}

	// Verify parent exists
	exists, _, err := svc.devicesStorage.DeviceGroups().SelectByID(ctx, *parentID)
	if err != nil {
		lFunc.Errorf("could not verify parent group existence: %s", err)
		return err
	}
	if !exists {
		lFunc.Errorf("parent group with ID '%s' does not exist", *parentID)
		return errs.ErrDeviceGroupNotFound
	}

	// Check for circular parent references in the hierarchy
	err = svc.validateNoCircularReference(ctx, groupID, *parentID)
	if err != nil {
		lFunc.Errorf("circular reference validation failed: %s", err)
		return err
	}

	return nil
}

// enrichGroupWithAncestorCriteria fetches ancestors and composes criteria with inheritance
func (svc DeviceManagerServiceBackend) enrichGroupWithAncestorCriteria(ctx context.Context, lFunc *logrus.Entry, group *models.DeviceGroup) error {
	// Store the count of this group's own criteria before composing with ancestors
	ownCriteriaCount := len(group.Criteria)

	// Get all ancestors to include parent filters in response
	lFunc.Debugf("fetching ancestors for device group '%s'", group.ID)
	ancestors, err := svc.devicesStorage.DeviceGroups().SelectAncestors(ctx, group.ID)
	if err != nil {
		lFunc.Errorf("could not get ancestors for device group '%s': %s", group.ID, err)
		return err
	}

	// Separate own criteria from ancestor criteria
	ownCriteria := group.Criteria
	inheritedCriteria := make([]models.DeviceGroupFilterOption, 0)

	// Collect criteria from all ancestors except the current group
	for _, ancestor := range ancestors {
		if ancestor.ID != group.ID {
			inheritedCriteria = append(inheritedCriteria, ancestor.Criteria...)
		}
	}

	// Compose: inherited first, then own
	allCriteria := make([]models.DeviceGroupFilterOption, 0, len(inheritedCriteria)+len(ownCriteria))
	allCriteria = append(allCriteria, inheritedCriteria...)
	allCriteria = append(allCriteria, ownCriteria...)

	// Set the composed criteria and track the own criteria count
	group.Criteria = allCriteria
	group.OwnCriteriaCount = ownCriteriaCount

	return nil
}
