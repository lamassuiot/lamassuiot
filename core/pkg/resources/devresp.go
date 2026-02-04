package resources

import "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"

type GetDevicesResponse struct {
	IterableList[models.Device]
}

type GetDeviceGroupsResponse struct {
	IterableList[models.DeviceGroup]
}
