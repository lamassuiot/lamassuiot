package helpers

import (
	"time"

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

func ValidateCAExpiration(expiration models.Validity, caExp time.Time) bool {
	if expiration.Type == models.Time {
		if caExp.Before(expiration.Time) {
			return false
		}
	} else {
		expTime := time.Now().Add(time.Duration(expiration.Duration))
		if caExp.Before(expTime) {
			return false
		}
	}
	return true
}
