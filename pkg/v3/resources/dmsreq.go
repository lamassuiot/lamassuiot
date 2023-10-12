package resources

import (
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
)

type CreateDMSBody struct {
	ID       string             `json:"id"`
	Name     string             `json:"name"`
	Metadata map[string]string  `json:"metadata"`
	Settings models.DMSSettings `json:"settings"`
}
