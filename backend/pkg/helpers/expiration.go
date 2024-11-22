package helpers

import (
	"time"

	"github.com/lamassuiot/lamassuiot/v3/core/pkg/models"
)

func ValidateExpirationTimeRef(input models.Expiration) bool {
	if input.Type == models.Duration && input.Duration == nil {
		return false
	} else if input.Type == models.Time && input.Time == nil {
		return false
	}
	return true
}

func ValidateCAExpiration(expiration models.Expiration, caExp time.Time) bool {
	if expiration.Type == models.Time {
		if caExp.Before(*expiration.Time) {
			return false
		}
	} else {
		expTime := time.Now().Add(time.Duration(*expiration.Duration))
		if caExp.Before(expTime) {
			return false
		}
	}
	return true
}
