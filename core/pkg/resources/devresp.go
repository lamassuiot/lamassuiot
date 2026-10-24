package resources

import "github.com/lamassuiot/lamassuiot/v4/core/pkg/models"

type GetDevicesResponse struct {
	IterableList[models.Device]
}

type GetDeviceEventsResponse struct {
	IterableList[models.DeviceEvent]
}

type GetDeviceGroupsResponse struct {
	IterableList[models.DeviceGroup]
}
