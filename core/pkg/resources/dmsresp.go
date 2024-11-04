package resources

import "github.com/lamassuiot/lamassuiot/v2/core/pkg/models"

type GetDMSsResponse struct {
	IterableList[models.DMS]
}
