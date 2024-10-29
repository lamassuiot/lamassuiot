package resources

import "github.com/lamassuiot/lamassuiot/v2/core/pkg/models"

type GetDevicesResponse struct {
	IterableList[models.Device]
}
