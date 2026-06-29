package resources

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

type GetDevicesResponse struct {
	resources.IterableList[models.Device]
}
