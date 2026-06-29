package helpers

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

func ValidateValidity(input models.Validity) bool {
	if input.Type == models.Duration && input.Duration == models.TimeDuration(0) {
		return false
	} else if input.Type == models.Time && input.Time.IsZero() {
		return false
	}

	return true
}
