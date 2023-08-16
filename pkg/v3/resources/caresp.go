package resources

import "github.com/lamassuiot/lamassuiot/pkg/v3/models"

type GetCAsResponse struct {
	IterableList[models.CACertificate]
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
