package resources

import (
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
)

type GetDevicesResponse struct {
	resources.IterableList[models.Device]
}
