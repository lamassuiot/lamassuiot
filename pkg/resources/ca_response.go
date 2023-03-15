package resources

import "github.com/lamassuiot/lamassuiot/pkg/models"

type GetCAsResponse struct {
	IterbaleList[models.CACertificate]
}

type GetCertsResponse struct {
	IterbaleList[models.Certificate]
}
