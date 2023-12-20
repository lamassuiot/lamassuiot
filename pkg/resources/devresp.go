package resources

import "github.com/lamassuiot/lamassuiot/v2/pkg/models"

type GetDevicesResponse struct {
	IterableList[models.Device]
}
