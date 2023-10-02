package resources

import "github.com/lamassuiot/lamassuiot/pkg/v3/models"

type GetDevicesResponse struct {
	IterableList[models.Device]
}
