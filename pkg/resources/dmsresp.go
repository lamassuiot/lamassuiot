package resources

import "github.com/lamassuiot/lamassuiot/pkg/models"

type CreateDMSResponse struct {
	PrivateKey string      `json:"private_key,omitempty"`
	DMS        *models.DMS `json:"dms"`
}

type GetDMSsResponse struct {
	IterbaleList[models.DMS]
}
