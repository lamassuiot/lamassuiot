package resources

import "github.com/lamassuiot/lamassuiot/v3/core/pkg/models"

type GetDMSsResponse struct {
	IterableList[models.DMS]
}
