package resources

import "github.com/lamassuiot/lamassuiot/pkg/v3/models"

type GetDMSsResponse struct {
	IterableList[models.DMS]
}
