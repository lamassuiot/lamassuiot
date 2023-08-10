package resources

import "github.com/lamassuiot/lamassuiot/pkg/v3/models"

type GetDevicesResponse struct {
	IterbaleList[models.Device]
}
