package resources

import (
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/resources"
)

type GetDevicesResponse struct {
	resources.IterableList[models.Device]
}
