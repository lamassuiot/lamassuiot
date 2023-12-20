package resources

import "github.com/lamassuiot/lamassuiot/v2/pkg/models"

type GetDMSsResponse struct {
	IterableList[models.DMS]
}
