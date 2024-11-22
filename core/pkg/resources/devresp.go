package resources

import "github.com/lamassuiot/lamassuiot/v3/core/pkg/models"

type GetDevicesResponse struct {
	IterableList[models.Device]
}
