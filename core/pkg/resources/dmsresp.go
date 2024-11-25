package resources

import "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"

type GetDMSsResponse struct {
	IterableList[models.DMS]
}
