package resources

import "github.com/lamassuiot/lamassuiot/pkg/models"

type GetDevicesResponse struct {
	IterbaleList[models.Device]
}
