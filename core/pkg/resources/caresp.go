package resources

import "github.com/lamassuiot/lamassuiot/v4/core/pkg/models"

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

type GetKeysResponse struct {
	IterableList[models.Key]
}
