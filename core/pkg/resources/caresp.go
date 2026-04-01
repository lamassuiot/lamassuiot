package resources

import "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"

type GetCAsResponse struct {
	IterableList[models.CACertificate]
}

type GetAlertsResponse struct {
	IterableList[models.AlertLatestEvent]
}

type GetItemsResponse[T any] struct {
	IterableList[T]
}

type GetCertsResponse struct {
	IterableList[models.Certificate]
}

type SignResponse struct {
	SignedData string `json:"signed_data"`
}

type VerifyResponse struct {
	Valid bool `json:"valid"`
}

type GetKeysResponse struct {
	IterableList[models.Key]
}
